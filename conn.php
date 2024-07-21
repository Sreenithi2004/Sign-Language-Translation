<?php
// MySQL Database connection details
$servername = "localhost";
$username = "root";
$password = "";
$database = "SignLanguageTranslation";

// Create connection
$conn = new mysqli($servername, $username, $password, $database);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if ($_POST['action'] === 'signup') {
        $username = $conn->real_escape_string($_POST['username']);
        $email = $conn->real_escape_string($_POST['email']);
        $password = $conn->real_escape_string($_POST['password']);

        // Hash the password
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        // SQL query to insert user data into database using prepared statement
        $sql = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("sss", $username, $email, $hashedPassword);

        if ($stmt->execute()) {
            echo "Sign Up successful";
        } else {
            echo "Error: " . $sql . "<br>" . $conn->error;
        }

        $stmt->close();
    } elseif ($_POST['action'] === 'signin') {
        $username = $conn->real_escape_string($_POST['username']);
        $password = $conn->real_escape_string($_POST['password']);

        // SQL query to check if user exists
        $sql = "SELECT * FROM users WHERE username=?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            // Verify hashed password
            $row = $result->fetch_assoc();
            if (password_verify($password, $row['password'])) {
                // Redirect based on username
                if ($username === 'admin') 
                    echo "Success-admin";
                else 
                    echo "Success-user";
            } else {
                echo "Failure";
            }
        } else {
            echo "Failure";
        }

        $stmt->close();
    }
}

// Close connection
$conn->close();
?>
