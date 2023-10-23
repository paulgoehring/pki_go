console.log("Hello World");

const fs = require('fs');

// Define the file path where the JWT is stored
const filePath = '/secrets/client.jwt';

// Read the JWT from the file
fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
        console.error(err);
        return;
    }

    // Parse the JWT data (if needed)
    const jwtToken = data.trim(); // JWT as a string

    // Use the JWT in your Node.js application
    console.log('JWT read from file:');
    console.log(jwtToken);

    // You can now parse and use the JWT token in your Node.js code.
});

