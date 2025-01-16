from flask import Flask, render_template, redirect, url_for, request, jsonify, make_response
import requests
import jwt
from datetime import timedelta, datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'
API_URL = "https://prices.openfoodfacts.org/api/v1/products"

JWT_SECRET = "eyJSb2xlIjoiQWRtaW4iLCJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkphdmFJblVzZSIsImV4cCI6MTczNjQ5ODQ2MywiaWF0IjoxNzM2NDk4NDYzfQ"
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_MINUTES = 5

# Simulated user storage (replace with a database in production)
user_store = {}
# Simulated cart storage for each user
user_cart_store = {}

@app.context_processor
def inject_year():
    return {'current_year': datetime.now().year}
def get_filtered_products(page, per_page=10):
    response = requests.get(API_URL)
    products = response.json().get('items', [])
    filtered_products = [
        product for product in products
        if product.get('product_name') and product.get('price_count') is not None and product.get('image_url')
    ]
    start = (page - 1) * per_page
    end = start + per_page
    return filtered_products[start:end], len(filtered_products)

def login_required(f):
    """Decorator to protect routes with JWT authentication."""
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('access_token')
        if not token:
            return redirect(url_for('login'))
        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            return redirect(url_for('login'))
        except jwt.InvalidTokenError:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function

def get_user_cart(username):
    """Retrieve the cart for a specific user."""
    if username not in user_cart_store:
        user_cart_store[username] = []  # Initialize an empty cart for new users
    return user_cart_store[username]

def save_user_cart(username, cart):
    """Save the cart for a specific user."""
    user_cart_store[username] = cart
def get_username_from_token():
    """Retrieve the username from the JWT token in cookies."""
    token = request.cookies.get('access_token')
    if not token:
        return None  # No token present

    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return decoded_token.get('username')
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None  # Invalid or expired token

@app.route('/update-cart', methods=['POST'])
def update_cart():
    username = get_username_from_token()
    if not username:
        return jsonify({"error": "User not logged in"}), 401  # Handle unauthenticated access

    data = request.json
    product_id = data.get('id')
    quantity = data.get('quantity')

    # Retrieve and update the user's cart
    cart = get_user_cart(username)
    if cart is None:
        return jsonify({"error": "Cart not found"}), 404  # Handle missing cart

    for item in cart:
        if item['id'] == product_id:
            item['quantity'] = quantity
            break
    else:
        return jsonify({"error": "Product not found in cart"}), 404  # Handle missing product

    # Save the updated cart
    save_user_cart(username, cart)

    return jsonify({"message": "Cart updated successfully!", "cart": cart})


@app.route('/remove-from-cart', methods=['POST'])
def remove_from_cart():
    username = get_username_from_token()
    if not username:
        return jsonify({"error": "User not logged in"}), 401  # Handle unauthenticated access

    data = request.json
    product_id = data.get('id')

    # Retrieve and update the user's cart
    cart = get_user_cart(username)
    if cart is None:
        return jsonify({"error": "Cart not found"}), 404  # Handle missing cart

    updated_cart = [item for item in cart if item['id'] != product_id]
    if len(updated_cart) == len(cart):
        return jsonify({"error": "Product not found in cart"}), 404  # Handle missing product

    # Save the updated cart
    save_user_cart(username, updated_cart)

    return jsonify({"message": "Product removed from cart!", "cart": updated_cart})



@app.route('/add-to-cart', methods=['POST'])
def add_to_cart():
    username = get_username_from_token()
    if not username:
        return jsonify({"error": "User not logged in"}), 401  # Handle unauthenticated access

    # Retrieve the user's cart (initialize if not present)
    cart = get_user_cart(username)
    if cart is None:
        cart = []  # Initialize an empty cart if it doesn't exist

    product = request.json
    # Check if the product already exists in the cart
    for item in cart:
        if item['id'] == product['id']:
            item['quantity'] += 1
            break
    else:
        # Add new product to the cart
        cart.append({"id": product['id'], "name": product['name'], "quantity": 1})

    # Save the updated cart for the user
    save_user_cart(username, cart)

    # Respond with the updated cart
    return jsonify({"message": "Product added to cart successfully!", "cart": cart})


@app.context_processor
def inject_user():
    token = request.cookies.get('access_token')
    if token:
        try:
            decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            return {'user': {'name': decoded_token['username'], 'is_authenticated': True}}
        except jwt.ExpiredSignatureError:
            return {'user': {'is_authenticated': False}}
        except jwt.InvalidTokenError:
            return {'user': {'is_authenticated': False}}
    return {'user': {'is_authenticated': False}}

def is_logged_in():
    """Check if the user is logged in based on the JWT in cookies."""
    token = request.cookies.get('access_token')
    if not token:
        return False
    try:
        jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return True
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return False
@app.route('/cart')
def cart():
    cart = get_user_cart(get_username_from_token())
    return render_template('cart.html', cart=cart)
@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    username = get_username_from_token()
    if not username:
        return redirect(url_for('login'))  # Redirect unauthenticated users to the login page

    # Retrieve the user's cart
    cart = get_user_cart(username)
    if not cart:
        return redirect(url_for('cart'))  # Redirect to the cart if it is empty

    if request.method == 'POST':
        # Simulate a checkout process
        # Example: Confirm order, process payment, send confirmation email, etc.
        
        # Clear the cart after successful checkout
        cart.clear()
        save_user_cart(username, cart)

        # Render a success page or provide confirmation message
        return render_template('checkout_success.html', message="Your order has been placed successfully!")

    # Calculate the total price (replace 10 with actual price logic for each product)
    total = sum(item['quantity'] * 10 for item in cart)

    # Render the checkout page
    return render_template('checkout.html', cart=cart, total=total)



@app.route('/register', methods=['GET', 'POST'])
def register():
    if is_logged_in():
        return redirect(url_for('home'))  # Redirect logged-in users to the home page
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if username in user_store:
            return render_template('register.html', error="Username already exists.")
        
        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match.")

        # Hash the password and store it
        hashed_password = generate_password_hash(password)
        user_store[username] = hashed_password

        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('home'))  # Redirect logged-in users to the home page
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username not in user_store or not check_password_hash(user_store[username], password):
            return render_template('login.html', error="Invalid username or password.")

        payload = {
            "username": username,
            "exp": datetime.utcnow() + timedelta(minutes=JWT_EXP_DELTA_MINUTES)
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        response = make_response(redirect(url_for('home')))
        response.set_cookie('access_token', token, httponly=True, max_age=300)
        return response
    return render_template('login.html')


@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('login')))
    response.set_cookie('access_token', '', expires=0)
    response.set_cookie('cart', '', expires=0)
    return response

@app.route('/')
@login_required
def home():
    page = request.args.get('page', 1, type=int)
    products, total_products = get_filtered_products(page)
    total_pages = (total_products + 9) // 10
    return render_template('home.html', products=products, page=page, total_pages=total_pages)

@app.route('/product/<int:product_id>')
@login_required
def product_detail(product_id):
    response = requests.get(f"{API_URL}/{product_id}")
    product = response.json()
    if product.get('product_name') and product.get('price_count') is not None and product.get('image_url'):
        return render_template('product_detail.html', product=product)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
