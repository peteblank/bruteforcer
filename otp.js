const http = require('http');
const Router = require('router');
const bodyParser = require('body-parser');
const finalhandler = require('finalhandler');

const router = Router();
const PORT = 3000;
const CORRECT_PIN = "543210";

// 1. MUST BE FIRST: Parse URL-encoded bodies (for ffuf standard POSTs)
router.use(bodyParser.urlencoded({ extended: true }));
// Parse JSON bodies (just in case)
router.use(bodyParser.json());

// 2. DEFINE ROUTES
router.post('/login', (req, res) => {
    // If the middleware worked, req.body will exist safely
    if (!req.body) {
        res.statusCode = 400;
        return res.end("Error: Body parsing failed.");
    }

    const userPin = req.body.pin;

    if (userPin === CORRECT_PIN) {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'text/plain');
        res.end("Access Granted: Welcome Admin!");
    } else {
        res.statusCode = 401;
        res.setHeader('Content-Type', 'text/plain');
        res.end("Access Denied: Invalid PIN.");
    }
});

// 3. CREATE THE SERVER
const server = http.createServer((req, res) => {
    router(req, res, finalhandler(req, res));
});

server.listen(PORT, () => {
    console.log(`Test server successfully running at http://localhost:${PORT}`);
    console.log(`Target PIN is: ${CORRECT_PIN}`);
});
