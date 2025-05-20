import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from neo4j import GraphDatabase
from werkzeug.security import generate_password_hash, check_password_hash
import flask_login
import requests
from datetime import datetime
from functools import wraps

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'dev-key-123'  

# Neo4j Configuration
NEO4J_URI = os.environ.get('NEO4J_URI', 'bolt://localhost:7687')
NEO4J_USER = os.environ.get('NEO4J_USER', 'neo4j')
NEO4J_PASSWORD = os.environ.get('NEO4J_PASSWORD', '123456789')
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# Flask-Login Setup
login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(flask_login.UserMixin):
    def __init__(self, user_id, username, email):
        self.id = user_id
        self.username = username
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    with driver.session() as session:
        result = session.run(
            "MATCH (u:User {id: $user_id}) RETURN u",
            user_id=user_id
        )
        user_data = result.single()
        if user_data:
            user_node = user_data['u']
            return User(user_node['id'], user_node['username'], user_node['email'])
    return None

# API Helpers
def get_book_details(identifier):
    """Fetch book details from Open Library, handling both ISBNs and OLIDs"""
    try:
        # Handle OLIDs (Open Library IDs)
        if identifier.startswith('OL'):
            url = f"https://openlibrary.org/works/{identifier}.json"
        # Handle ISBNs
        else:
            url = f"https://openlibrary.org/api/books?bibkeys=ISBN:{identifier}&format=json&jscmd=data"
        
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            
            # Process OLID response
            if identifier.startswith('OL'):
                return {
                    'title': data.get('title', 'Unknown'),
                    'authors': [a.get('author', {}).get('key', 'Unknown') for a in data.get('authors', [])],
                    'cover': f"https://covers.openlibrary.org/b/olid/{identifier}-L.jpg",
                    'isbn': identifier
                }
            # Process ISBN response
            else:
                book_data = data.get(f'ISBN:{identifier}', {})
                return {
                    'title': book_data.get('title', 'Unknown'),
                    'authors': book_data.get('authors', [{'name': 'Unknown'}]),
                    'cover': book_data.get('cover', {}).get('large', 
                             f"https://covers.openlibrary.org/b/isbn/{identifier}-L.jpg"),
                    'isbn': identifier
                }
    except Exception as e:
        print(f"[ERROR] Failed to fetch book details: {str(e)}")
    return None

def search_books(query, limit=5):
    url = f"https://openlibrary.org/search.json?q={query}&limit={limit}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            books = data.get('docs', [])
            
            processed_books = []
            for book in books:
                # Extract all possible identifiers
                identifiers = []
                
                # Check all ISBN fields
                for field in ['isbn', 'isbn_10', 'isbn_13']:
                    if field in book:
                        if isinstance(book[field], list):
                            identifiers.extend(book[field])
                        elif isinstance(book[field], str):
                            identifiers.append(book[field])
                
                # Use Open Library ID as fallback
                if 'key' in book:
                    olid = book['key'].split('/')[-1]
                    identifiers.append(olid)
                
                # Only include books with at least one identifier
                if identifiers:
                    processed_books.append({
                        'title': book.get('title', 'Unknown'),
                        'author_name': book.get('author_name', ['Unknown']),
                        'identifiers': identifiers,
                        'first_publish_year': book.get('first_publish_year'),
                        'cover_i': book.get('cover_i')
                    })
            
            return processed_books
            
    except Exception as e:
        print(f"[ERROR] Search failed: {str(e)}")
    return []

def get_trending_books():
    """Get trending books from Open Library"""
    url = "https://openlibrary.org/trending/daily.json?limit=10"
    try:
        response = requests.get(url, timeout=5)
        works = response.json().get('works', [])
        return [{
            'isbn': work['key'].split('/')[-1],
            'title': work.get('title', 'Unknown'),
            'author': work.get('author_name', ['Unknown'])[0],
            'cover': f"https://covers.openlibrary.org/b/olid/{work['cover_edition_key']}-M.jpg"
        } for work in works]
    except requests.RequestException:
        return []

# Recommendation Engine
def get_recommendations(user_id):
    print(f"\n[DEBUG] Starting recommendations for user: {user_id}")
    try:
        # 1. Get user preferences from Neo4j
        with driver.session() as session:
            print("[DEBUG] Fetching user preferences...")
            prefs = session.run(
                """
                MATCH (u:User {id: $user_id})-[:HAS_PREFERENCE]->(pref)
                RETURN labels(pref)[0] as type, pref.name as name
                """,
                user_id=user_id
            ).data()
            print(f"[DEBUG] User preferences: {prefs}")

            # 2. Get already interacted books
            print("[DEBUG] Fetching saved/reviewed books...")
            interacted = session.run(
                """
                MATCH (u:User {id: $user_id})
                RETURN coalesce(u.saved_books, []) as saved,
                       [(u)-[:WROTE]->(r) | r.isbn] as reviewed
                """,
                user_id=user_id
            ).single()
            print(f"[DEBUG] Saved books: {interacted['saved']}")
            print(f"[DEBUG] Reviewed books: {interacted['reviewed']}")

        excluded = set(interacted['saved'] + interacted['reviewed'])
        print(f"[DEBUG] Excluded ISBNs: {excluded}")

        # 3. Build query parts from preferences
        query_parts = []
        for pref in prefs:
            if pref['type'] == 'Author':
                query_parts.append(f"author:\"{pref['name']}\"")
            else:
                query_parts.append(f"subject:\"{pref['name']}\"")
        print(f"[DEBUG] Search queries: {query_parts}")

        # [Rest of the function remains the same...]
        results = []
        seen_identifiers = set()

        for query in query_parts[:3]:  # Now properly defined
            books = search_books(query, limit=5)
            print(f"[DEBUG] Found {len(books)} processed books for: {query}")
            
            for book in books:
                for identifier in book['identifiers']:
                    if identifier and identifier not in excluded and identifier not in seen_identifiers:
                        seen_identifiers.add(identifier)
                        
                        # Determine cover image
                        if identifier.startswith('OL'):
                            cover_url = f"https://covers.openlibrary.org/b/olid/{identifier}-M.jpg"
                        elif book.get('cover_i'):
                            cover_url = f"https://covers.openlibrary.org/b/id/{book['cover_i']}-M.jpg"
                        else:
                            cover_url = "https://via.placeholder.com/150x200?text=No+Cover"
                        
                        # Add to results
                        results.append({
                            'id': identifier,
                            'title': book['title'],
                            'author': ', '.join(book['author_name']),
                            'cover': cover_url,
                            'year': book.get('first_publish_year')
                        })
                        print(f"[DEBUG] Added book: {book['title']} (ID: {identifier})")
                        break
        
        if not results:
            print("[WARNING] No results after processing. Using trending books.")
            trending = get_trending_books()
            results = [b for b in trending if b['isbn'] not in excluded][:10]
        
        return results[:10]
    
    except Exception as e:
        print(f"[ERROR] Recommendation failed: {str(e)}")
        return get_trending_books()
    
# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not flask_login.current_user.is_authenticated:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


# Routes
@app.route('/')
def index():
    if flask_login.current_user.is_authenticated:
        books = get_recommendations(flask_login.current_user.id)
        return render_template('index.html', books=books)
    return render_template('index.html')



@app.route('/book/<isbn>')
def book_details(isbn):
    book = get_book_details(isbn)
    if not book:
        flash('Book not found', 'error')
        return redirect(url_for('index'))
    
    # Check if saved
    saved = False
    if flask_login.current_user.is_authenticated:
        with driver.session() as session:
            saved = session.run(
                "MATCH (u:User {id: $user_id}) RETURN $isbn IN coalesce(u.saved_books, []) as saved",
                user_id=flask_login.current_user.id,
                isbn=isbn
            ).single()['saved']
    
    # Get reviews
    with driver.session() as session:
        reviews = session.run(
            """
            MATCH (u:User)-[r:WROTE]->(rev:Review {isbn: $isbn})
            RETURN u.username as username, 
                   rev.rating as rating, 
                   rev.comment as comment, 
                   rev.date as date,
                   id(r) as review_id
            ORDER BY rev.date DESC
            """,
            isbn=isbn
        ).data()
    
    
    return render_template('book.html', book=book, reviews=reviews, saved=saved, isbn=isbn)



@app.route('/save_book', methods=['POST'])
@login_required
def save_book():
    print("\n[DEBUG SAVE BOOK]")
    isbn = request.form.get('isbn')
    action = request.form.get('action')
    
    print(f"ISBN: {isbn}, Action: {action}")
    
    if not isbn or action not in ['save', 'remove']:
        flash('Invalid request', 'error')
        return redirect(url_for('index'))

    with driver.session() as session:
        try:
            if action == 'save':
                print("[DEBUG] Attempting to save book")
                result = session.run(
                    """
                    MATCH (u:User {id: $user_id})
                    SET u.saved_books = coalesce(u.saved_books, []) + $isbn
                    RETURN u.saved_books as saved
                    """,
                    user_id=flask_login.current_user.id,
                    isbn=isbn
                )
                print(f"[DEBUG] Saved books: {result.single()['saved']}")
                flash('Book saved to your reading list', 'success')
            else:
                print("[DEBUG] Attempting to remove book")
                result = session.run(
                    """
                    MATCH (u:User {id: $user_id})
                    SET u.saved_books = [x IN u.saved_books WHERE x <> $isbn]
                    RETURN size(u.saved_books) as remaining
                    """,
                    user_id=flask_login.current_user.id,
                    isbn=isbn
                )
                print(f"[DEBUG] Books remaining: {result.single()['remaining']}")
                flash('Book removed from your reading list', 'info')
        except Exception as e:
            print(f"[ERROR] Save book operation failed: {str(e)}")
            flash('Operation failed', 'error')
    
    return redirect(url_for('book_details', isbn=isbn))

@app.route('/submit_review', methods=['POST'])
@login_required
def submit_review():
    print("\n[DEBUG REVIEW SUBMISSION]")
    print(f"Form data: {request.form}")
    isbn = request.form.get('isbn')
    rating = request.form.get('rating')
    comment = request.form.get('comment')
    
    print(f"Received - ISBN: {isbn}, Rating: {rating}, Comment: {comment}")
    
    if not rating or not comment:
        flash('Rating and comment are required', 'error')
        return redirect(url_for('book_details', isbn=isbn))
    
    try:
        rating = int(rating)
        if not (1 <= rating <= 5):
            flash('Rating must be between 1 and 5', 'error')
            return redirect(url_for('book_details', isbn=isbn))
    except ValueError:
        flash('Invalid rating format', 'error')
        return redirect(url_for('book_details', isbn=isbn))

    with driver.session() as session:
        print("[DEBUG] Attempting to save review to Neo4j")
        try:
            result = session.run(
                """
                MATCH (u:User {id: $user_id})
                CREATE (u)-[:WROTE]->(r:Review {
                    rating: $rating,
                    comment: $comment,
                    date: datetime(),
                    isbn: $isbn
                })
                RETURN r
                """,
                user_id=flask_login.current_user.id,
                rating=rating,
                comment=comment,
                isbn=isbn
            )
            print(f"[DEBUG] Review created: {result.single()}")
            flash('Review submitted successfully!', 'success')
        except Exception as e:
            print(f"[ERROR] Failed to create review: {str(e)}")
            flash('Failed to submit review', 'error')
    
    return redirect(url_for('book_details', isbn=isbn))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('signup'))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters!', 'error')
            return redirect(url_for('signup'))
        
        with driver.session() as session:
            # Check if username exists
            result = session.run(
                "MATCH (u:User {username: $username}) RETURN u",
                username=username
            )
            if result.single():
                flash('Username already exists!', 'error')
                return redirect(url_for('signup'))
            
            # Create new user
            hashed_password = generate_password_hash(password)
            user_id = str(uuid.uuid4())
            
            session.run(
                """
                CREATE (u:User {
                    id: $id,
                    username: $username,
                    email: $email,
                    password: $password,
                    created_at: datetime(),
                    saved_books: []
                })
                """,
                id=user_id,
                username=username,
                email=email,
                password=hashed_password
            )
            
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = True if request.form.get('remember') else False
        
        with driver.session() as session:
            result = session.run(
                "MATCH (u:User {username: $username}) RETURN u",
                username=username
            )
            user_data = result.single()
            
            if not user_data:
                flash('Invalid username or password', 'error')
                return redirect(url_for('login'))
            
            user_node = user_data['u']
            if check_password_hash(user_node['password'], password):
                user = User(user_node['id'], user_node['username'], user_node['email'])
                flask_login.login_user(user, remember=remember)
                next_page = request.args.get('next')
                return redirect(next_page or url_for('profile'))
            else:
                flash('Invalid username or password', 'error')
                return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    flask_login.logout_user()
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    with driver.session() as session:
        # Get user preferences
        preferences = session.run(
            """
            MATCH (u:User {id: $user_id})-[:HAS_PREFERENCE]->(pref)
            RETURN labels(pref)[0] as type, pref.name as name
            """,
            user_id=flask_login.current_user.id
        )
        
        # Get user reviews
        reviews = session.run(
            """
            MATCH (u:User {id: $user_id})-[:WROTE]->(r:Review)
            RETURN r.rating as rating, r.comment as comment, 
                   r.date as date, r.isbn as isbn
            ORDER BY r.date DESC
            """,
            user_id=flask_login.current_user.id
        )
        
        # Get saved books
        saved_books = session.run(
            "MATCH (u:User {id: $user_id}) RETURN u.saved_books as saved_books",
            user_id=flask_login.current_user.id
        ).single()['saved_books'] or []
        
        # Process data
       # In your profile() route, replace the preferences section with:
        prefs = {'Genre': [], 'Author': [], 'Theme': []}  # Added 'Theme'
        for pref in preferences:
            pref_type = pref['type']
            # Handle both old and new preference types
            if pref_type in prefs:
                prefs[pref_type].append(pref['name'])
            else:
                print(f"[WARNING] Unknown preference type: {pref_type}")
                # Optionally add to a catch-all category
                prefs.setdefault('Other', []).append(pref['name'])
        review_list = []
        for review in reviews:
            book_data = get_book_details(review['isbn'])
            if book_data:
                review_data = {
                    'rating': review['rating'],
                    'comment': review['comment'],
                    'date': review['date'],
                    'book': book_data
                }
                review_list.append(review_data)
        
        saved_list = []
        for isbn in saved_books:
            book_data = get_book_details(isbn)
            if book_data:
                book_data['isbn'] = isbn
                saved_list.append(book_data)
        
        return render_template('profile.html', 
                            preferences=prefs, 
                            reviews=review_list, 
                            saved_books=saved_list)

@app.route('/preferences', methods=['GET', 'POST'])
@login_required
def preferences():
    if request.method == 'POST':
        genres = request.form.getlist('genres')
        authors = request.form.getlist('authors')
        themes = request.form.getlist('themes')  # Added themes
        
        with driver.session() as session:
            # Clear existing preferences
            session.run(
                """
                MATCH (u:User {id: $user_id})-[r:HAS_PREFERENCE]->(any)
                DELETE r
                """,
                user_id=flask_login.current_user.id
            )
            
            # Add new genre preferences
            for genre in genres:
                session.run(
                    """
                    MERGE (g:Genre {name: $genre})
                    WITH g
                    MATCH (u:User {id: $user_id})
                    MERGE (u)-[:HAS_PREFERENCE]->(g)
                    """,
                    genre=genre, 
                    user_id=flask_login.current_user.id
                )
            
            # Add new author preferences
            for author in authors:
                session.run(
                    """
                    MERGE (a:Author {name: $author})
                    WITH a
                    MATCH (u:User {id: $user_id})
                    MERGE (u)-[:HAS_PREFERENCE]->(a)
                    """,
                    author=author, 
                    user_id=flask_login.current_user.id
                )
            
            # Add new theme preferences
            for theme in themes:  # Added theme handling
                session.run(
                    """
                    MERGE (t:Theme {name: $theme})
                    WITH t
                    MATCH (u:User {id: $user_id})
                    MERGE (u)-[:HAS_PREFERENCE]->(t)
                    """,
                    theme=theme,
                    user_id=flask_login.current_user.id
                )
            
            flash('Preferences updated successfully!', 'success')
            return redirect(url_for('profile'))
    
    # GET request - show preferences form
    with driver.session() as session:
        # Get user's current preferences
        user_prefs = {'Genre': [], 'Author': [], 'Theme': []}
        prefs_result = session.run(
            """
            MATCH (u:User {id: $user_id})-[:HAS_PREFERENCE]->(pref)
            RETURN labels(pref)[0] as type, pref.name as name
            """,
            user_id=flask_login.current_user.id
        )
        
        for pref in prefs_result:
            if pref['type'] in user_prefs:  # Only add known types
                user_prefs[pref['type']].append(pref['name'])
        
        # Get all available options
        genres = session.run("MATCH (g:Genre) RETURN g.name as name ORDER BY g.name")
        authors = session.run("MATCH (a:Author) RETURN a.name as name ORDER BY a.name")
        themes = session.run("MATCH (t:Theme) RETURN t.name as name ORDER BY t.name")
        
        return render_template('preferences.html', 
                            genres=[record['name'] for record in genres],
                            authors=[record['name'] for record in authors],
                            themes=[record['name'] for record in themes],
                            user_prefs=user_prefs)
    
@app.route('/api/saved_books')
@login_required
def api_saved_books():
    with driver.session() as session:
        saved_books = session.run(
            "MATCH (u:User {id: $user_id}) RETURN u.saved_books as saved_books",
            user_id=flask_login.current_user.id
        ).single()['saved_books'] or []
        
        books = []
        for isbn in saved_books[:10]:  # Limit to 10 books for performance
            book_data = get_book_details(isbn)
            if book_data:
                book_data['isbn'] = isbn
                books.append(book_data)
        
        return jsonify(books)

@app.route('/api/user/reviews')
@login_required
def api_user_reviews():
    with driver.session() as session:
        reviews = session.run(
            """
            MATCH (u:User {id: $user_id})-[:WROTE]->(r:Review)
            RETURN r.rating as rating, r.comment as comment, 
                   r.date as date, r.isbn as isbn
            ORDER BY r.date DESC
            LIMIT 10
            """,
            user_id=flask_login.current_user.id
        ).data()
        
        review_list = []
        for review in reviews:
            book_data = get_book_details(review['isbn'])
            if book_data:
                review_data = {
                    'rating': review['rating'],
                    'comment': review['comment'],
                    'date': review['date'].strftime('%Y-%m-%d'),
                    'book': book_data
                }
                review_list.append(review_data)
        
        return jsonify(review_list)
@app.route('/edit_review', methods=['POST'])
@login_required
def edit_review():
    try:
        review_id = int(request.form['review_id'])
        isbn = request.form['isbn']
        rating = int(request.form['rating'])
        comment = request.form['comment'].strip()

        if not (1 <= rating <= 5):
            raise ValueError("Rating must be between 1-5")

        with driver.session() as session:
            updated = session.run(
                """
                MATCH (u:User {id: $user_id})-[r:WROTE]->(:Review)
                WHERE id(r) = $review_id
                SET r.rating = $rating,
                    r.comment = $comment,
                    r.date = datetime()
                RETURN r
                """,
                user_id=flask_login.current_user.id,
                review_id=review_id,
                rating=rating,
                comment=comment
            ).single()

            if not updated:
                raise ValueError("Review not found or unauthorized")

        flash('Review updated successfully!', 'success')
    except Exception as e:
        print(f"Error updating review: {str(e)}")
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('book_details', isbn=isbn))

@app.route('/delete_review', methods=['POST'])
@login_required
def delete_review():
    try:
        review_id = int(request.form['review_id'])
        isbn = request.form['isbn']

        with driver.session() as session:
            deleted = session.run(
                """
                MATCH (u:User {id: $user_id})-[r:WROTE]->(:Review)
                WHERE id(r) = $review_id
                DELETE r
                RETURN count(r) as deleted
                """,
                user_id=flask_login.current_user.id,
                review_id=review_id
            ).single()

            if not deleted or deleted['deleted'] == 0:
                raise ValueError("Review not found or unauthorized")

        flash('Review deleted successfully!', 'success')
    except Exception as e:
        print(f"Error deleting review: {str(e)}")
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('book_details', isbn=isbn))

if __name__ == '__main__':
    app.run(debug=True)