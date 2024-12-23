import streamlit as st
import hashlib
import sqlite3
import requests
import pandas as pd
from streamlit_option_menu import option_menu

# Function to securely hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Function to register user in the database
def register_user(username, email, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 
                       (username, email, hash_password(password)))
        conn.commit()
    except sqlite3.IntegrityError:
        return False  # Username already exists
    finally:
        conn.close()
    return True

# Function to validate login credentials
def validate_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    if result and result[0] == hash_password(password):
        return True
    return False

# Function to fetch user details
def get_user_details(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username, email FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    return result

# Initialize the database
init_db()

# Function to fetch and display market data
def fetch_market_data():
    st.subheader("Market Data")
    api_key = "0U2453MMW64RB2KY"  # Replace with your Alpha Vantage API key
    base_url = "https://www.alphavantage.co/query"

    symbol = st.text_input("Enter stock symbol (e.g., AAPL)", value="AAPL")
    if st.button("Fetch Data"):
        params = {
            "function": "TIME_SERIES_DAILY",
            "symbol": symbol,
            "outputsize": "compact",
            "apikey": api_key
        }
        try:
            response = requests.get(base_url, params=params)
            response.raise_for_status()

            data = response.json()
            if "Error Message" in data:
                st.error("Error with API key or symbol. Please check your inputs.")
                return

            time_series = data.get("Time Series (Daily)", {})
            if not time_series:
                st.error("Failed to fetch data. Check your API key or symbol.")
                return

            df = pd.DataFrame.from_dict(time_series, orient="index")
            df = df.rename(columns={
                "1. open": "Open",
                "2. high": "High",
                "3. low": "Low",
                "4. close": "Close",
                "5. volume": "Volume"
            })
            df.index = pd.to_datetime(df.index)
            df = df.sort_index()

            st.write("### Daily Stock Prices")
            st.dataframe(df.head(20))

            # Plot the line chart
            st.line_chart(df["Close"])

        except requests.exceptions.RequestException as e:
            st.error(f"Error fetching data: {e}")

# Function for login page
def login():
    st.subheader("Login")
    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")

    if st.button("Login"):
        if validate_user(username, password):
            st.session_state['logged_in'] = True
            st.session_state['username'] = username
            st.session_state['page'] = "Home"
            st.success(f"Welcome, {username}!")
        else:
            st.error("Invalid username or password.")

# Function for registration page
def register():
    st.subheader("Register")
    username = st.text_input("Username", key="register_username")
    email = st.text_input("Email", key="register_email")
    password = st.text_input("Password", type="password", key="register_password")
    confirm_password = st.text_input("Confirm Password", type="password", key="confirm_password")

    if st.button("Register"):
        if not username or not email or not password:
            st.warning("Please fill in all the fields.")
        elif password != confirm_password:
            st.warning("Passwords do not match!")
        else:
            success = register_user(username, email, password)
            if success:
                st.success("Registration successful! You can now log in.")
            else:
                st.warning("Username already exists!")

# Function for home page
def show_home_page():
    st.title("Home Page")
    fetch_market_data()
    # Add Logout button on top-right corner of Home page
    if st.button("Logout", key="home_logout"):
        logout()

# Function for user details page
def show_user_details():
    username = st.session_state['username']
    user_data = get_user_details(username)
    if user_data:
        st.subheader("User Details")
        st.write(f"Username: {user_data[0]}")
        st.write(f"Email: {user_data[1]}")
    # Add Logout button on top-right corner of User Details page
    if st.button("Logout", key="user_details_logout"):
        logout()

# Function to logout and clear session
def logout():
    st.session_state['logged_in'] = False
    st.session_state['page'] = "Login/Register"
    st.session_state['username'] = None
    st.success("You have logged out.")

# Main function
def main():
    # Display the title above the navigation bar
    st.title("Global Market Analyzer")
    
    if 'page' not in st.session_state:
        st.session_state['page'] = "Login/Register"
    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False
    if 'username' not in st.session_state:
        st.session_state['username'] = None

    # Navigation
    menu_options = ["Login/Register", "Home", "User Details"]
    if st.session_state['logged_in']:
        menu_options = ["Home", "User Details"]

    selected_option = option_menu(
        menu_title=None,
        options=menu_options,
        icons=["person", "house", "info-circle"],
        menu_icon="menu-up",
        default_index=0,
        orientation="horizontal"
    )

    # Render pages based on state
    if selected_option == "Login/Register":
        if st.session_state['logged_in']:
            st.session_state['page'] = "Home"
        else:
            st.session_state['page'] = "Login/Register"
            page_option = st.sidebar.radio("Choose an option:", ["Login", "Register"])
            if page_option == "Login":
                login()
            else:
                register()
    elif selected_option == "Home":
        if not st.session_state['logged_in']:
            st.warning("Please log in first.")
            st.session_state['page'] = "Login/Register"
        else:
            st.session_state['page'] = "Home"
            show_home_page()
    elif selected_option == "User Details":
        if not st.session_state['logged_in']:
            st.warning("Please log in first.")
            st.session_state['page'] = "Login/Register"
        else:
            st.session_state['page'] = "User Details"
            show_user_details()

if __name__ == "__main__":
    main()
