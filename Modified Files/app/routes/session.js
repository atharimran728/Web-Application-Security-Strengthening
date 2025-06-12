const logger = require('../../logger');
const UserDAO = require("../data/user-dao").UserDAO;
const AllocationsDAO = require("../data/allocations-dao").AllocationsDAO;
const {
    environmentalScripts
} = require("../../config/config");
const bcrypt = require('bcrypt'); // Import bcrypt for password hashing and comparison
const jwt = require('jsonwebtoken'); // Import jsonwebtoken for JWT creation and verification

/*
 * IMPORTANT SECURITY NOTE:
 * 'your-secret-key' must be replaced with a strong, securely generated,
 * and environment-variable-stored secret in a production environment.
 * Do NOT hardcode secrets in production applications.
 */
const JWT_SECRET = 'qwertyxyz123';

/* The SessionHandler must be constructed with a connected db */
function SessionHandler(db) {
    "use strict";

    const userDAO = new UserDAO(db);
    const allocationsDAO = new AllocationsDAO(db);

    /**
     * Prepares initial allocation data for a new user.
     * This function is called after a user successfully signs up.
     * @param {object} user - The user object for whom to prepare data.
     * @param {function} next - The next middleware function in the stack.
     */
    const prepareUserData = (user, next) => {
        // Generate random allocation percentages for stocks, funds, and bonds
        const stocks = Math.floor((Math.random() * 40) + 1);
        const funds = Math.floor((Math.random() * 40) + 1);
        const bonds = 100 - (stocks + funds);

        allocationsDAO.update(user._id, stocks, funds, bonds, (err) => {
            if (err) {
                // Log error if allocation update fails
                logger.error(`Error updating allocations for user ID: ${user._id}. Error: ${err.message}`, {
                    stack: err.stack
                });
                return next(err); // Pass the error to the next middleware
            }
            // Log successful allocation update
            logger.info(`Allocations updated for user ID: ${user._id}`);
        });
    };

    /**
     * Middleware to verify the JWT token from the Authorization header.
     * If valid, it attaches the decoded user ID to `req.userId`.
     * If invalid or missing, it sends an appropriate error response.
     * @param {object} req - The Express request object.
     * @param {object} res - The Express response object.
     * @param {function} next - The next middleware function.
     */
    const verifyToken = (req, res, next) => {
        // Get the Authorization header
        const authHeader = req.headers.authorization;

        // Check if Authorization header is missing
        if (!authHeader) {
            logger.warn(`Access denied: No authorization header provided from IP: ${req.ip}`);
            return res.status(401).json({ error: "Access Denied: No Token Provided!" });
        }

        // Extract the token (expects "Bearer <token>")
        const token = authHeader.split(' ')[1];

        // Check if token is missing after "Bearer"
        if (!token) {
            logger.warn(`Access denied: No token found in authorization header from IP: ${req.ip}`);
            return res.status(401).json({ error: "Access Denied: No Token Provided!" });
        }

        try {
            // Verify the token using the secret key
            const decoded = jwt.verify(token, JWT_SECRET);
            req.userId = decoded.id; // Attach the user ID from the token payload to the request object
            logger.info(`Token verified for user ID: ${req.userId}`);
            next(); // Proceed to the next middleware or route handler
        } catch (err) {
            // Handle various token verification errors (e.g., malformed, expired, invalid signature)
            logger.error(`Invalid Token from IP: ${req.ip}. Error: ${err.message}`, { stack: err.stack });
            return res.status(400).json({ error: "Invalid Token." });
        }
    };

    /**
     * Middleware to check if the authenticated user is an administrator.
     * It first verifies the JWT and then checks the user's `isAdmin` status from the database.
     * @param {object} req - The Express request object.
     * @param {object} res - The Express response object.
     * @param {function} next - The next middleware function.
     */
    this.isAdminUserMiddleware = (req, res, next) => {
        verifyToken(req, res, () => { // First, verify the JWT token
            // If verifyToken passed, req.userId will be available
            if (req.userId) {
                userDAO.getUserById(req.userId, (err, user) => {
                    if (err) {
                        logger.error(`Error in isAdminUserMiddleware for user ID: ${req.userId}. Error: ${err.message}`, {
                            stack: err.stack
                        });
                        return next(err);
                    }
                    // Check if user exists and has admin privileges
                    if (user && user.isAdmin) {
                        logger.info(`Admin access granted for user ID: ${req.userId}`);
                        return next(); // User is an admin, proceed
                    } else {
                        // User is not an admin or does not exist
                        logger.warn(`Unauthorized admin access attempt for user ID: ${req.userId || 'unknown'} from IP: ${req.ip}`);
                        return res.status(403).json({ error: "Forbidden: Not an admin user." }); // 403 Forbidden for API
                    }
                });
            }
            // If req.userId is not set, verifyToken would have already sent a response.
            // This 'else' branch should ideally not be reached if verifyToken works as expected.
        });
    };

    /**
     * Middleware to check if the user is logged in (i.e., has a valid JWT).
     * It relies on the `verifyToken` middleware to populate `req.userId`.
     * @param {object} req - The Express request object.
     * @param {object} res - The Express response object.
     * @param {function} next - The next middleware function.
     */
    this.isLoggedInMiddleware = (req, res, next) => {
        verifyToken(req, res, () => { // First, verify the JWT token
            // If verifyToken passed, req.userId will be available
            if (req.userId) {
                logger.info(`User ID: ${req.userId} is logged in (via JWT).`);
                return next(); // User is logged in, proceed
            }
            // If verifyToken fails, it already sends a 401. This part is largely for conceptual clarity.
            logger.warn(`User is not logged in. IP: ${req.ip}`);
            return res.status(401).json({ error: "Unauthorized: Please log in." }); // 401 Unauthorized for API
        });
    };

    /**
     * Displays the login page.
     * @param {object} req - The Express request object.
     * @param {object} res - The Express response object.
     * @param {function} next - The next middleware function.
     */
    this.displayLoginPage = (req, res, next) => {
        logger.info(`Login page displayed to IP: ${req.ip}`);
        // Renders the login HTML page
        return res.render("login", {
            userName: "",
            password: "",
            loginError: "",
            environmentalScripts
        });
    };

    /**
     * Handles user login requests.
     * It validates user credentials against the database (using bcrypt.compare internally in UserDAO)
     * and, upon success, issues a JWT.
     * @param {object} req - The Express request object (containing userName and password in body).
     * @param {object} res - The Express response object.
     * @param {function} next - The next middleware function.
     */
    this.handleLoginRequest = (req, res, next) => {
        const {
            userName,
            password
        } = req.body;
        logger.info(`Login attempt for username: ${userName} from IP: ${req.ip}`);

        // The userDAO.validateLogin method is assumed to internally use bcrypt.compare
        // to verify the provided password against the hashed password stored in the DB.
        userDAO.validateLogin(userName, password, (err, user) => {
            const invalidUserNameErrorMessage = "Invalid username";
            const invalidPasswordErrorMessage = "Invalid password";

            if (err) {
                // Handle specific login errors
                if (err.noSuchUser) {
                    const sanitizedUserName = String(userName).replace(/(\r\n|\r|\n)/g, '_');
                    logger.warn(`Failed login: No such user '${sanitizedUserName}' from IP: ${req.ip}`);
                    return res.status(401).json({ loginError: invalidUserNameErrorMessage }); // Send JSON error
                } else if (err.invalidPassword) {
                    const sanitizedUserName = String(userName).replace(/(\r\n|\r|\n)/g, '_');
                    logger.warn(`Failed login: Invalid password for user '${sanitizedUserName}' from IP: ${req.ip}`);
                    return res.status(401).json({ loginError: invalidPasswordErrorMessage }); // Send JSON error
                } else {
                    // Handle other unexpected errors during login validation
                    logger.error(`Error during login validation for user '${userName}' from IP: ${req.ip}. Error: ${err.message}`, {
                        stack: err.stack
                    });
                    return next(err); // Pass the error to the Express error handling middleware
                }
            }

            // If user successfully validated, issue a JWT
            const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });
            logger.info(`User '${user.userName}' (ID: ${user._id}) successfully logged in from IP: ${req.ip}. JWT issued.`);

            // Send the token and user's admin status in the JSON response
            return res.json({ token, isAdmin: user.isAdmin });
        });
    };

    /**
     * Handles user logout. In a JWT-based system, logout is primarily client-side
     * (deleting the token from storage). This function can be used to clear any
     * server-side session data if traditional sessions are still partially in use.
     * @param {object} req - The Express request object.
     * @param {object} res - The Express response object.
     */
    this.displayLogoutPage = (req, res) => {
        // If traditional sessions are still used for other data, destroy them.
        // For a pure JWT system, this part is less relevant as state is client-side.
        if (req.session && req.session.userId) {
            const userId = req.session.userId; // Capture userId before session destroy
            req.session.destroy((err) => {
                if (err) {
                    logger.error(`Error destroying session for user ID: ${userId}. Error: ${err.message}`, { stack: err.stack });
                    return res.status(500).send("Logout failed on server."); // Inform client of server-side session error
                }
                logger.info(`User ID: ${userId} logged out (session destroyed). IP: ${req.ip}`);
                res.redirect("/"); // Redirect to home/login page
            });
        } else {
            logger.info(`Logout requested without active server-side session. IP: ${req.ip}`);
            res.redirect("/"); // Simply redirect if no server-side session exists
        }
    };

    /**
     * Displays the signup page.
     * @param {object} req - The Express request object.
     * @param {object} res - The Express response object.
     */
    this.displaySignupPage = (req, res) => {
        logger.info(`Signup page displayed to IP: ${req.ip}`);
        res.render("signup", {
            userName: "",
            password: "",
            passwordError: "",
            email: "",
            userNameError: "",
            emailError: "",
            verifyError: "",
            environmentalScripts
        });
    };

    /**
     * Validates user input during the signup process.
     * @param {string} userName - The username.
     * @param {string} firstName - The first name.
     * @param {string} lastName - The last name.
     * @param {string} password - The password.
     * @param {string} verify - The password verification input.
     * @param {string} email - The email address.
     * @param {object} errors - An object to store validation error messages.
     * @returns {boolean} True if all inputs are valid, false otherwise.
     */
    const validateSignup = (userName, firstName, lastName, password, verify, email, errors) => {
        // Regular expressions for validation
        const USER_RE = /^.{1,20}$/;
        const FNAME_RE = /^.{1,100}$/;
        const LNAME_RE = /^.{1,100}$/;
        const EMAIL_RE = /^[\S]+@[\S]+\.[\S]+$/;
        // Password must be at least 8 characters, include numbers, lowercase and uppercase letters.
        const PASS_RE = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/;

        // Initialize error messages
        errors.userNameError = "";
        errors.firstNameError = "";
        errors.lastNameError = "";
        errors.passwordError = "";
        errors.verifyError = "";
        errors.emailError = "";

        if (!USER_RE.test(userName)) {
            errors.userNameError = "Invalid user name (1-20 characters).";
            logger.warn(`Signup validation failed for user '${userName}': Invalid user name.`);
            return false;
        }
        if (!FNAME_RE.test(firstName)) {
            errors.firstNameError = "Invalid first name (1-100 characters).";
            logger.warn(`Signup validation failed for user '${userName}': Invalid first name.`);
            return false;
        }
        if (!LNAME_RE.test(lastName)) {
            errors.lastNameError = "Invalid last name (1-100 characters).";
            logger.warn(`Signup validation failed for user '${userName}': Invalid last name.`);
            return false;
        }
        if (!PASS_RE.test(password)) {
            errors.passwordError = "Password must be at least 8 characters and include numbers, lowercase and uppercase letters.";
            logger.warn(`Signup validation failed for user '${userName}': Weak password.`);
            return false;
        }
        if (password !== verify) {
            errors.verifyError = "Passwords must match";
            logger.warn(`Signup validation failed for user '${userName}': Passwords do not match.`);
            return false;
        }
        if (email && !EMAIL_RE.test(email)) { // Email is optional, but if provided, it must be valid
            errors.emailError = "Invalid email address";
            logger.warn(`Signup validation failed for user '${userName}': Invalid email address.`);
            return false;
        }
        return true; // All validations passed
    };

    /**
     * Handles user signup requests.
     * It validates input, hashes the password using bcrypt, adds the user to the database,
     * and upon success, issues a JWT.
     * @param {object} req - The Express request object (containing signup data in body).
     * @param {object} res - The Express response object.
     * @param {function} next - The next middleware function.
     */
    this.handleSignup = async (req, res, next) => {
        const {
            email,
            userName,
            firstName,
            lastName,
            password,
            verify
        } = req.body;

        logger.info(`Signup attempt for username: ${userName} from IP: ${req.ip}`);

        const errors = {
            "userName": userName,
            "email": email
        };

        // Validate the signup form data
        if (validateSignup(userName, firstName, lastName, password, verify, email, errors)) {
            try {
                // Hash the password asynchronously using bcrypt
                const hashedPassword = await bcrypt.hash(password, 10); // 10 is the salt rounds
                logger.info(`Password successfully hashed for user '${userName}'`);

                // Check if the username already exists in the database
                userDAO.getUserByUserName(userName, (err, user) => {
                    if (err) {
                        logger.error(`Error during signup user lookup for username '${userName}': ${err.message}`, {
                            stack: err.stack
                        });
                        return next(err); // Pass the error to the next middleware
                    }

                    if (user) {
                        // Username already taken
                        errors.userNameError = "User name already in use. Please choose another";
                        logger.warn(`Signup failed: Username '${userName}' already in use from IP: ${req.ip}`);
                        return res.render("signup", { // Render signup page with error for HTML forms
                            ...errors,
                            environmentalScripts
                        });
                    }

                    // Add the new user to the database with the hashed password
                    userDAO.addUser(userName, firstName, lastName, hashedPassword, email, (err, newUser) => {
                        if (err) {
                            logger.error(`Error adding new user '${userName}': ${err.message}`, {
                                stack: err.stack
                            });
                            return next(err); // Pass the error
                        }

                        logger.info(`New user '${userName}' (ID: ${newUser._id}) successfully created.`);

                        // Prepare initial data for the new user (e.g., allocations)
                        prepareUserData(newUser, next);

                        // Issue a JWT for the newly registered user
                        const token = jwt.sign({ id: newUser._id }, JWT_SECRET, { expiresIn: '1h' });
                        logger.info(`New user '${newUser.userName}' (ID: ${newUser._id}) signed up. JWT issued.`);

                        // Send the token and isAdmin status in the JSON response
                        return res.status(201).json({ token, isAdmin: newUser.isAdmin }); // 201 Created for successful resource creation
                    });
                });
            } catch (hashError) {
                // Catch any errors during the password hashing process
                logger.error(`Error hashing password for user '${userName}': ${hashError.message}`, {
                    stack: hashError.stack
                });
                return next(hashError); // Pass the hashing error
            }
        } else {
            // Validation failed, re-render the signup page with error messages
            logger.warn(`Signup attempt failed validation for username: ${userName} from IP: ${req.ip}. Errors: ${JSON.stringify(errors)}`);
            return res.render("signup", {
                ...errors,
                environmentalScripts
            });
        }
    };

    /**
     * Displays the welcome/dashboard page after successful login.
     * This route requires a valid JWT to identify the user.
     * @param {object} req - The Express request object.
     * @param {object} res - The Express response object.
     * @param {function} next - The next middleware function.
     */
    this.displayWelcomePage = (req, res, next) => {
        verifyToken(req, res, () => { // First, verify the JWT token
            const userId = req.userId; // userId is populated by verifyToken

            if (!userId) {
                // This scenario should be caught by verifyToken middleware, but as a safeguard.
                logger.info(`Welcome page access attempt without valid JWT. IP: ${req.ip}`);
                return res.status(401).send("Unauthorized: Please log in to view this page.");
            }

            userDAO.getUserById(userId, (err, doc) => {
                if (err) {
                    logger.error(`Error fetching user ID: ${userId} for welcome page. Error: ${err.message}`, {
                        stack: err.stack
                    });
                    return next(err);
                }
                if (doc) {
                    doc.userId = userId; // Attach userId for view rendering purposes
                    logger.info(`Dashboard displayed for user ID: ${userId}`);
                    // Renders the dashboard HTML page with user data
                    return res.render("dashboard", {
                        ...doc,
                        environmentalScripts
                    });
                } else {
                    // This indicates a valid token but user not found in DB (e.g., deleted user)
                    logger.warn(`Invalid user ID: ${userId} found in token. User not in DB. IP: ${req.ip}.`);
                    // In a real application, you might want to force the client to clear the invalid token.
                    return res.status(401).send("Unauthorized: User associated with token not found.");
                }
            });
        });
    };
}

module.exports = SessionHandler;
