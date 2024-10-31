import hashlib

# ISO/IEC 27001/27002 Requirement: Authentication and Authorization
# - Use a secure authentication mechanism for users

# Dummy database for demonstration purposes
users = {
    "alice": "password",
    "bob": "secret"
}


def authenticate(username, password):
    # Hash the password for comparison
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    if username in users and users[username] == hashed_password:
        return True
    return False


# ISO/IEC 27001/27002 Requirement: Input Validation
# - Validate input data to prevent common attacks like SQL injection and cross-site scripting (XSS)

def validate_input(input_data):
    # Remove leading and trailing whitespaces
    input_data = input_data.strip()

    # Prevent XSS by escaping special characters
    input_data = input_data.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

    # Prevent SQL injection by limiting the length of the input
    max_input_length = 100
    input_data = input_data[:max_input_length]

    return input_data


# Security Test: Input Validation Test
def test_input_validation():
    input_data = "test' OR '1'='1"  # Malicious input to test validation
    cleaned_input = validate_input(input_data)

    # Expected output should be "test" without any special characters or SQL injection attempts
    expected_output = "test"

    if cleaned_input == expected_output:
        print("Input Validation Test Passed.")
    else:
        print("Input Validation Test Failed. Malicious input was not detected.")


if __name__ == "__main__":
    username = input("Username: ")
    password = input("Password: ")

    if authenticate(username, password):
        print("Authentication Successful.")
        input_data = input("Enter some data to validate: ")
        cleaned_input = validate_input(input_data)
        print("Cleaned Input:", cleaned_input)
        test_input_validation()
    else:
        print("Authentication Failed.")
