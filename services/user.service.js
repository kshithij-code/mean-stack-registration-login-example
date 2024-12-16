const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config.json');

// MongoDB Connection
const client = new MongoClient(config.connectionString);
const dbName = 'your-database-name'; // Replace with your database name
let db;

// Initialize MongoDB connection
(async () => {
    try {
        await client.connect();
        db = client.db(dbName);
        console.log('Connected to MongoDB');
    } catch (err) {
        console.error('MongoDB connection error:', err);
    }
})();

// Service object
const service = {
    authenticate,
    getById,
    create,
    update,
    delete: _delete, // "delete" is a reserved keyword, use "_delete"
};

module.exports = service;

// Authenticate user
async function authenticate(username, password) {
    try {
        const user = await db.collection('users').findOne({ username });
        if (user && bcrypt.compareSync(password, user.hash)) {
            // Authentication successful
            return jwt.sign({ sub: user._id }, config.secret);
        } else {
            // Authentication failed
            return null;
        }
    } catch (err) {
        throw new Error(err.message);
    }
}

// Get user by ID
async function getById(_id) {
    try {
        const user = await db.collection('users').findOne({ _id: new ObjectId(_id) });
        if (!user) return null;
        // Return user without password hash
        return omitHash(user);
    } catch (err) {
        throw new Error(err.message);
    }
}

// Create new user
async function create(userParam) {
    try {
        // Check if username is already taken
        const existingUser = await db.collection('users').findOne({ username: userParam.username });
        if (existingUser) {
            throw new Error(`Username "${userParam.username}" is already taken`);
        }

        // Hash password
        const user = {
            ...userParam,
            hash: bcrypt.hashSync(userParam.password, 10),
        };
        delete user.password; // Remove plain-text password

        // Insert user into database
        await db.collection('users').insertOne(user);
    } catch (err) {
        throw new Error(err.message);
    }
}

// Update user
async function update(_id, userParam) {
    try {
        const user = await db.collection('users').findOne({ _id: new ObjectId(_id) });

        if (!user) {
            throw new Error('User not found');
        }

        if (user.username !== userParam.username) {
            // Check if the new username is already taken
            const existingUser = await db.collection('users').findOne({ username: userParam.username });
            if (existingUser) {
                throw new Error(`Username "${userParam.username}" is already taken`);
            }
        }

        // Fields to update
        const updateFields = {
            firstName: userParam.firstName,
            lastName: userParam.lastName,
            username: userParam.username,
        };

        // Update password if provided
        if (userParam.password) {
            updateFields.hash = bcrypt.hashSync(userParam.password, 10);
        }

        // Update the user in the database
        await db.collection('users').updateOne(
            { _id: new ObjectId(_id) },
            { $set: updateFields }
        );
    } catch (err) {
        throw new Error(err.message);
    }
}

// Delete user
async function _delete(_id) {
    try {
        await db.collection('users').deleteOne({ _id: new ObjectId(_id) });
    } catch (err) {
        throw new Error(err.message);
    }
}

// Helper function to omit hash from user object
function omitHash(user) {
    const { hash, ...userWithoutHash } = user;
    return userWithoutHash;
}
