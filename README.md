# Password Manager

This is a Python-based Password Manager application with a graphical user interface (GUI) built using Tkinter. The application allows users to securely store, retrieve, generate, and manage their passwords.

## Features

- Secure Encryption: Passwords are encrypted using the Fernet symmetric encryption from the cryptography library.

- Password Management: Add, view, and delete passwords for different services.

- Password Validation: Ensure passwords meet strength requirements (length, uppercase, lowercase, special characters).

- Password Generation: Generate strong, random passwords of customizable length.

- Clipboard Copy: Copy usernames and passwords to the clipboard with a single click.

- Tab-Based Interface: Easy navigation between stored passwords and password generation.

## Requirements

- Python 3.7+

- `tkinter` (pre-installed with Python)

- `cryptography`

## Installation

1. Clone the repository:

```bash
git clone https://github.com/your-username/password-manager.git
```
```bash
cd password-manager
```

2. Install dependencies:
```bash
pip install cryptography
```
3. Run the application:
```bash
python password_manager.py
```

## Usage

1. Adding a Password

- Navigate to the Passwords tab.

- Click on Add Password.

- Enter the service name, username, and password (or generate a strong password).

- Save the password. It will be securely encrypted and stored.
<br><br>

2. Viewing a Password

- Select a service from the password list.

- Click on View Password to see the username and password.

- Copy the username or password to the clipboard using the provided buttons.
  <br><br>

3. Deleting a Password

- Select a service from the password list.

- Click on Delete Password to remove it.
  <br><br>

4. Generating a Password

- Navigate to the Generate Password tab.

- Specify the desired length (minimum 8 characters).

- Click Generate to create a random password.

- Save the generated password to a service or copy it to the clipboard.
<br><br>

## File Structure

`password_manager.py`: Main application file.

`key.key`: Automatically generated encryption key (stored securely).

`passwords.enc`: Encrypted file storing all passwords.

## Security Notes

- The application uses Fernet encryption to securely encrypt and decrypt password data.

- The `key.key` file is required to access the encrypted passwords. Keep this file secure and do not share it.

- Always use strong master passwords and enable additional security measures if integrating with external systems.

## Future Enhancements

- Implement a master password to further secure access to the application.

- Add support for exporting and importing password data.

- Integrate cloud backup for encrypted password storage.

- Provide more customization options for password generation.

## License

This project is licensed under the MIT License.
