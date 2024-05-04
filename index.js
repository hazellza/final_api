const express = require('express')
const cors = require('cors')
const mysql = require('mysql2')
const bcrypt = require('bcrypt')
require('dotenv').config()
const app = express()


app.use(cors())
app.use(express.json())

const connection = mysql.createConnection(process.env.DATABASE_URL)

app.get('/', (req, res) => {
    res.send('Hello world!!')
})

app.get('/users', (req, res) => {
    connection.query(
        'SELECT * FROM users',
        function (err, results, fields) {
            res.send(results)
        }
    )
})

app.get('/users/:id', (req, res) => {
    const id = req.params.id;
    connection.query(
        'SELECT * FROM users WHERE id = ?', [id],
        function (err, results, fields) {
            res.send(results)
        }
    )
})


app.post('/register', (req, res) => {
    connection.query(
        'SELECT * FROM `users` WHERE `username` = ?',
        [req.body.username],
        function (err, results, fields) {
            if (err) {
                console.error('Error in checking username:', err);
                res.status(500).send('Error checking username');
            } else {
                if (results.length > 0) {
                    res.status(400).send('Username already exists');
                } else {
                    // ทำการ hash หรือเข้ารหัส password ก่อนที่จะ เก็ยลง ฐานข้อมูล
                    bcrypt.hash(req.body.password, 10, function (err, hash) {
                        if (err) {
                            console.error('Error hashing password:', err);
                            res.status(500).send('Error hashing password');
                        } else {
                            connection.query(
                                'INSERT INTO `users` (`fname`, `lname`, `username`, `password`, `phonenumber`, `avatar`) VALUES (?, ?, ?, ?, ?, ?)',
                                [req.body.fname, req.body.lname, req.body.username, hash, req.body.phonenumber, req.body.avatar],
                                function (err, results, fields) {
                                    if (err) {
                                        console.error('Error in POST /register:', err);
                                        res.status(500).send('Error adding user');
                                    } else {
                                        res.status(201).send('Register successful');
                                    }
                                }
                            );
                        }
                    });
                }
            }
        }
    );
});


app.post('/login', function (req, res) {
    connection.query(
        'SELECT * FROM `users` WHERE username = ?',
        [req.body.username],
        function (err, results) {
            if (err) {
                console.error('Error in login:', err);
                res.status(500).send('Error logging in');
            } else {
                if (results.length > 0) {
                    // ดูว่า username มีใน ฐานไหม
                    bcrypt.compare(req.body.password, results[0].password, function (err, result) {
                        if (err) {
                            console.error('Error comparing passwords:', err);
                            res.status(500).send('Error logging in');
                        } else {
                            if (result) {
                                // Passwords match, login successful
                                res.status(200).send('Login successful');
                            } else {
                                // Passwords don't match
                                res.status(401).send('Login failed');
                            }
                        }
                    });
                } else {
                    // User not found
                    res.status(404).send('User not found');
                }
            }
        }
    );
});



app.put('/users', (req, res) => {
    connection.query(
        'UPDATE `users` SET `fname`=?, `lname`=?, `username`=?, `password`=?, `phonenumber`=?, `avatar`=? WHERE id =?',
        [req.body.fname, req.body.lname, req.body.username, req.body.password, req.body.phonenumber, req.body.avatar, req.body.id],
        function (err, results, fields) {
            res.send(results)
        }
    )
})

app.delete('/users', (req, res) => {
    connection.query(
        'DELETE FROM `users` WHERE id =?',
        [req.body.id],
        function (err, results, fields) {
            res.send(results)
        }
    )
})



/////////////////// ATTRACTION API //////////////////

app.listen(process.env.PORT || 3000, () => {
    console.log('CORS-enabled web server listening on port 3000')
})

