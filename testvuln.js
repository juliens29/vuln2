
// Fonction vulnérable à l'injection SQL (OWASP A01:2021 - Injection)
function a01Positif(userInput) {
    const pg = require('pg');
    const connectionString = 'postgresql://user:password@localhost:5432/mydb';
    const client = new pg.Client(connectionString);

    client.connect();

    // Cette requête est vulnérable à une injection SQL car elle concatène directement l'entrée utilisateur
    const query = `SELECT * FROM users WHERE username = '${userInput}'`;

    client.query(query, (err, res) => {
        if (err) throw err;
        console.log(res.rows);
    });

    client.end();
}

// Vulnérabilités:
// - CWE-89: SQL Injection
// - CVSS: 9.8 (Critique)
// - CVE: Non spécifique, varie selon l'implémentation
// - Autres référentiels: SANS Top 25 "Injection Flaws", Burp Suite Tests for SQL Injection
// - Outil de test recommandé: Peut être identifié par des outils SAST, DAST, et IAST

// Fonction souvent identifiée incorrectement comme vulnérable à l'injection (faux positif)
function a01Negatif(userInput) {
    console.log(`Received input: ${userInput}`);
    // Faux positif: bien que cette fonction utilise la template string pour intégrer l'entrée utilisateur,
    // il n'y a aucune exécution de code ou requête SQL qui serait affectée par l'injection.
}

// Commentaire:
// - CWE potentiel: CWE-20 (Improper Input Validation)
// - CVSS: Variable, généralement bas si c'est un faux positif
// - CVE: Non spécifique, dépend de l'utilisation
// - Termes associés: Faux Positif
// - Outil de test recommandé: Les outils SAST peuvent faussement identifier ce code comme vulnérable


// Fonction vulnérable à des problèmes de gestion de session (OWASP A02:2021 - Failles de gestion de l'authentification et de la session)
function a02Positif(username, password) {
    const session = require('express-session');
    const express = require('express');
    const app = express();

    app.use(session({
        secret: 'verysecret', // Utilisation d'une clé secrète faible
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false } // Cookies non sécurisés envoyés sur HTTP
    }));

    app.post('/login', (req, res) => {
        // Simuler une validation d'identifiants
        if (username === 'admin' && password === 'password') {
            req.session.loggedIn = true; // État de connexion stocké sans précautions supplémentaires
            res.send('Vous êtes connecté.');
        } else {
            res.send('Échec de la connexion.');
        }
    });

    app.listen(3000);
}

// Vulnérabilités:
// - CWE-287: Improper Authentication
// - CVSS: 7.5 (Haute)
// - CVE: Non spécifique, dépend de l'implémentation
// - Autres référentiels: SANS Top 25 "Insecure Interaction Between Components"
// - Outil de test recommandé: DAST, IAST


// Fonction souvent identifiée incorrectement comme ayant des failles de gestion de session (faux positif)
function a02Negatif() {
    const express = require('express');
    const app = express();

    app.get('/safeEndpoint', (req, res) => {
        res.send('Ce point d’accès est sûr.');
    });

    app.listen(3000);
}

// Commentaire:
// - Faux positif: certains outils DAST pourraient signaler ce point d'accès comme vulnérable
//   à des attaques de session, simplement parce qu'il n'implémente pas explicitement des contrôles de session,
//   mais ceci est un endpoint sans état, donc il n'y a aucun risque lié à la session ici.
// - CWE-200: Information Exposure (faux positif basé sur une mauvaise interprétation)
// - CVSS: Bas, si c'est un faux positif
// - CVE: Non spécifique, dépend de l'interprétation de l'outil
// - Outil de test recommandé: SAST (pour identifier des faux positifs)



//   Fonction vulnérable à l'exposition de données sensibles (OWASP A03:2021 - Exposition de Données Sensibles)
function a03Positif() {
    const crypto = require('crypto');
    const fs = require('fs');

    // Générer une clé AES avec une taille de clé insuffisante (128 bits utilisé ici)
    const key = crypto.randomBytes(16); // 128 bits sont moins sécurisés pour certains contextes
    const cipher = crypto.createCipher('aes-128-ecb', key);

    let sensitiveData = 'Ceci est un texte très sensible.';
    let encrypted = cipher.update(sensitiveData, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // Stockage du texte chiffré dans un fichier sans sécurisation adéquate
    fs.writeFileSync('encrypted.txt', encrypted);
    console.log('Data encrypted and stored without secure practices.');
}

// Vulnérabilités:
// - CWE-312: Cleartext Storage of Sensitive Information
// - CVSS: 5.9 (Moyenne)
// - CVE: Non spécifique, dépend de l'implémentation
// - Autres référentiels: SANS Top 25 "Insecure Cryptographic Storage"
// - Outil de test recommandé: IAST, DAST pour l'analyse de l'implémentation en runtim

// Fonction souvent identifiée incorrectement comme vulnérable à l'exposition de données sensibles (faux positif)
function a03Negatif() {
    const log = require('console-log-level')({ level: 'info' });

    // Log des informations qui peuvent être considérées sensibles par des outils automatisés, mais qui ne le sont pas.
    log.info('Starting application... No sensitive data exposed.');

    // Cette utilisation des logs est souvent marquée à tort comme une fuite d'informations sensibles
    log.debug('Debug mode is now active.');
}

// Commentaire:
// - Faux positif potentiel: CWE-215: Information Exposure Through Debug Information
// - CVSS: Bas, si c'est un faux positif
// - CVE: Non spécifique, dépend de l'interprétation
// - Termes associés: Faux Positif
// - Outil de test recommandé: SAST pour identifier les faux positifs liés à des logs inoffensifs


// Fonction vulnérable en raison de contrôles d'accès défaillants (OWASP A04:2021 - Contrôles d'Accès Défaillants)
function a04Positif() {
const express = require('express');
const app = express();

// Middleware qui simule une vérification d'authentification très basique
app.use((req, res, next) => {
    if (req.query.apiKey === '12345') {
        next(); // Accès autorisé avec une clé API simple
    } else {
        res.status(403).send('Accès refusé');
    }
});

// Endpoint administratif exposé sans vérifications de rôle suffisantes
app.get('/admin', (req, res) => {
    // Tous les utilisateurs avec la clé API peuvent accéder à cet endpoint
    res.send('Accès administratif accordé');
});

app.listen(3000);
}

// Vulnérabilités:
// - CWE-284: Improper Access Control
// - CVSS: 8.1 (Élevée)
// - CVE: Non spécifique, varie selon l'implémentation
// - Autres référentiels: SANS Top 25 "Insecure Direct Object References"
// - Outil de test recommandé: IAST, DAST pour analyser l'accès en temps réel

// Fonction souvent identifiée incorrectement comme ayant des failles de contrôle d'accès (faux positif)
function a04Negatif() {
    const express = require('express');
    const app = express();

    // Middleware pour authentifier tous les utilisateurs
    app.use((req, res, next) => {
        console.log('Authenticating...');
        // Ici, tous les utilisateurs sont considérés comme authentifiés pour cet endpoint public
        req.user = { id: '123', role: 'user' };
        next();
    });

    // Endpoint qui semble exposer des données sensibles sans contrôles d'accès appropriés
    app.get('/profile', (req, res) => {
        // Les informations retournées semblent sensibles, mais elles sont génériques et non spécifiques à un utilisateur
        res.json({
            message: 'Profile information is publicly available.',
            user: req.user.id,
            role: req.user.role
        });
    });

    app.listen(3000);
    console.log('Server running on port 3000');
}

// Commentaire:
// - Faux positif potentiel: certains outils DAST ou SAST peuvent détecter ce code comme une fuite d'informations utilisateur en raison de la présence d'un ID et d'un rôle utilisateur dans la réponse.
// - CWE-284: Improper Access Control (potentiel faux positif)
// - CVSS: Bas, si c'est un faux positif
// - CVE: Non spécifique, dépend de l'interprétation de l'outil
// - Outil de test recommandé: SAST pour évaluer le code source, IAST pour analyser le comportement à l'exécution


// Fonction vulnérable à une mauvaise configuration de sécurité (OWASP A05:2021 - Security Misconfiguration)
function a05Positif() {
    const express = require('express');
    const app = express();

    // Configuration dangereuse: détaillant trop d'informations lors des erreurs
    app.use(express.json());
    app.get('/api', (req, res) => {
        throw new Error('Something went wrong!');
    });

    // Gestion d'erreur exposant des détails sensibles
    app.use((err, req, res, next) => {
        res.status(500).send({ error: err.message, stack: err.stack });
    });

    app.listen(3000);
}

// Vulnérabilités:
// - CWE-209: Information Exposure Through an Error Message
// - CVSS: 5.3 (Moyenne)
// - CVE: Non spécifique, varie selon l'implémentation
// - Autres référentiels: SANS Top 25 "Error Handling"
// - Outil de test recommandé: DAST pour observer les fuites d'informations via les réponses aux erreurs

// Fonction souvent identifiée incorrectement comme vulnérable à une mauvaise configuration de sécurité (faux positif spécifique à A05)
function a05Negatif() {
    const express = require('express');
    const app = express();

    // Endpoint qui retourne des détails qui semblent être des configurations sensibles
    app.get('/system-info', (req, res) => {
        // Les données ici sont intentionnellement exposées et simulées pour des tests
        res.json({
            version: "1.0.0",
            environment: "test",
            debugMode: false
        });
    });

    app.listen(3000);
    console.log("Server for testing environment details running on port 3000");
}

// Commentaire:
// - Faux positif potentiel: certains outils DAST ou SAST peuvent détecter cet endpoint comme une fuite de configuration.
// - En réalité, les informations fournies ici sont intentionnellement non sensibles et destinées à des fins de diagnostic interne ou de tests.
// - CWE-16: Configuration
// - CVSS: Bas, si c'est un faux positif
// - CVE: Non spécifique, dépend de l'interprétation de l'outil
// - Termes associés: Faux Positif spécifique à l'A05
// - Outil de test recommandé: IAST pour comprendre le contexte d'exécution


// Fonction vulnérable due à l'utilisation de composants avec des failles connues (OWASP A06:2021 - Vulnerable and Outdated Components)
function A06Positif() {
    const express = require('express@4.15.0'); // Version vulnérable d'Express
    const app = express();

    app.get('/', (req, res) => {
        res.send('This version of Express is known to have several security flaws.');
    });

    app.listen(3000);
}

// Vulnérabilités:
// - CWE-937: Using Components with Known Vulnerabilities
// - CVSS: 9.0 (Haute)
// - CVE: CVE-2017-16026, CVE-2018-3716 (exemple de CVEs liés à cette version d'Express)
// - Autres référentiels: SANS Top 25 "Using Components with Known Vulnerabilities"
// - Outil de test recommandé: SAST pour détecter les versions de bibliothèques, DAST et IAST pour observer les impacts potentiels en exécution

// Fonction souvent identifiée incorrectement comme vulnérable en raison de l'utilisation de composants (faux positif spécifique à A06)
function A06Negatif() {
    const lodash = require('lodash@4.17.20'); // Version sécurisée de lodash, parfois faussement reportée comme vulnérable

    const array = [1, 2, 3];
    lodash.reverse(array); // Utilisation simple de lodash

    console.log(array);
}

// Commentaire:
// - Faux positif potentiel: certains outils peuvent mal interpréter des versions sécurisées de bibliothèques comme vulnérables.
// - CWE-937: Using Components with Known Vulnerabilities (faux positif)
// - CVSS: Bas, si c'est un faux positif
// - CVE: Non applicable pour les faux positifs
// - Termes associés: Faux Positif spécifique à l'A06
// - Outil de test recommandé: SAST pour vérifier les versions des composants, DAST et IAST pour validation


// Fonction vulnérable à une identification et authentification défaillantes (OWASP A07:2021 - Identification and Authentication Failures)
function A07Positif() {
const express = require('express');
const bodyParser = require('body-parser');
const app = express();
app.use(bodyParser.json());

// Simuler une base de données d'utilisateurs en mémoire
const users = [
    { id: 1, username: 'admin', password: 'admin123' } // Mauvaise pratique: mot de passe en clair
];

// Endpoint de login vulnérable
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username && u.password === password);
    if (user) {
        res.status(200).send('Login successful');
    } else {
        res.status(401).send('Authentication failed');
    }
});

app.listen(3000);
}

// Vulnérabilités:
// - CWE-287: Improper Authentication
// - CVSS: 9.8 (Haute)
// - CVE: Non spécifique, varie selon l'implémentation
// - Autres référentiels: SANS Top 25 "Cleartext Storage of Sensitive Information"
// - Outil de test recommandé: DAST pour tester le flux d'authentification, SAST pour détecter les pratiques de codage sécurisé

// Fonction souvent identifiée incorrectement comme vulnérable à des failles d'authentification (faux positif spécifique à A07)
function A07Negatif() {
const express = require('express');
const app = express();

// Endpoint de vérification de statut souvent mal interprété comme un point de contrôle d'accès
app.get('/health-check', (req, res) => {
    res.status(200).send('Server is running');
});

app.listen(3000);
}

// Commentaire:
// - Faux positif potentiel: certains outils peuvent marquer cet endpoint comme un risque d'authentification,
//   car il ne requiert pas d'authentification pour accéder à un endpoint qui pourrait sembler critique.
// - CWE-306: Missing Authentication for Critical Function (faux positif)
// - CVSS: Bas, si c'est un faux positif
// - CVE: Non spécifique, dépend de l'interprétation de l'outil
// - Termes associés: Faux Positif spécifique à l'A07
// - Outil de test recommandé: SAST pour analyser le contexte du code, DAST pour comprendre les permissions d'accès



// Fonction vulnérable à des failles de sérialisation (OWASP A08:2021 - Software and Data Integrity Failures)
function A08Positif() {
const express = require('express');
const bodyParser = require('body-parser');
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

app.post('/submit', (req, res) => {
    // Simuler la sérialisation d'un objet utilisateur avec une évaluation directe
    let userSerialized = `{"user":"${req.body.user}", "data":"${req.body.data}"}`;
    let userObj = eval('(' + userSerialized + ')');  // Utilisation dangereuse d'eval pour désérialiser

    // Réponse basée sur l'objet désérialisé
    res.send(`Received data from user: ${userObj.user}`);
});

app.listen(3000);
}

// Vulnérabilités:
// - CWE-502: Deserialization of Untrusted Data
// - CVSS: 9.1 (Haute)
// - CVE: Non spécifique, dépend de l'implémentation
// - Autres référentiels: SANS Top 25 "Improper Input Validation"
// - Outil de test recommandé: DAST pour tester des entrées malveillantes, SAST pour détecter l'usage de 'eval

// Fonction souvent identifiée incorrectement comme ayant des failles de sérialisation (faux positif spécifique à A08)
function A08Negatif() {
const express = require('express');
const app = express();

app.get('/data', (req, res) => {
    // Envoyer une chaîne JSON simple qui pourrait être interprétée comme une sérialisation non sécurisée
    res.json({ message: "This is just a static message, not actual serialization data." });
});

app.listen(3000);
}

// Commentaire:
// - Faux positif potentiel: certains outils peuvent détecter ce comportement comme une faille de sérialisation.
// - En réalité, aucune donnée sensible ou complexe n'est sérialisée ou désérialisée.
// - CWE-502: Deserialization of Untrusted Data (faux positif)
// - CVSS: Bas, si c'est un faux positif
// - CVE: Non spécifique, dépend de l'interprétation de l'outil
// - Outil de test recommandé: SAST pour analyser la gestion des données


// Fonction vulnérable à des failles de journalisation et de surveillance (OWASP A09:2021 - Security Logging and Monitoring Failures)
function A09Positif() {
    const express = require('express');
    const app = express();

    app.use(express.json());

    app.post('/login', (req, res) => {
        const { username, password } = req.body;
        // Simuler la vérification des identifiants sans journalisation adéquate
        if (username === 'admin' && password === 'admin123') {
            res.status(200).send('Login successful');
        } else {
            // Aucune trace des échecs de connexion, exposant le système à des attaques par force brute sans détection
            res.status(401).send('Login failed');
        }
    });

    app.listen(3000);
}

// Vulnérabilités:
// - CWE-778: Insufficient Logging
// - CVSS: 6.5 (Moyenne)
// - CVE: Non spécifique, dépend de l'implémentation
// - Autres référentiels: SANS Top 25 "Insufficient Logging & Monitoring"
// - Outil de test recommandé: DAST pour identifier le manque de réponses des journaux lors des tests d'intrusion


// Fonction souvent identifiée incorrectement comme ayant des failles de journalisation (faux positif spécifique à A09)
function A09Negatif() {
    const express = require('express');
    const app = express();
    const winston = require('winston');  // Utilisation de Winston pour la journalisation

    // Configuration du logger Winston
    const logger = winston.createLogger({
        level: 'info',
        format: winston.format.json(),
        transports: [
            new winston.transports.File({ filename: 'error.log', level: 'error' }),
            new winston.transports.File({ filename: 'combined.log' })
        ]
    });

    app.use(express.json());

    app.post('/login', (req, res) => {
        const { username, password } = req.body;
        // Simuler la vérification des identifiants avec journalisation interne
        if (username === 'admin' && password === 'admin123') {
            logger.info('Login successful for admin');
            res.status(200).send('Login successful');
        } else {
            logger.error(`Login failed for username: ${username}`);
            // Ici, il semble qu'il n'y ait pas de journalisation car rien n'est visible à l'extérieur
            res.status(401).send('Login failed');
        }
    });

    app.listen(3000);
    console.log("Server started on port 3000");
}

// Commentaire:
// - Faux positif potentiel: malgré l'apparence d'un manque de surveillance extérieure,
//   tous les événements sont correctement journalisés dans des fichiers internes.
// - CWE-778: Insufficient Logging (faux positif)
// - CVSS: Bas, si c'est un faux posit


// Fonction vulnérable à des failles de contrôle des accès au serveur (OWASP A10:2021 - Server-Side Request Forgery (SSRF))
function A10Positif() {
    const express = require('express');
    const axios = require('axios');
    const app = express();

    app.use(express.json());

    app.post('/fetch-data', async (req, res) => {
        const { url } = req.body;  // Reçoit l'URL de l'utilisateur sans aucune validation ou sanitization
        try {
            const response = await axios.get(url);  // Vulnérable à SSRF
            res.status(200).send(response.data);
        } catch (error) {
            res.status(500).send('Failed to fetch data');
        }
    });

    app.listen(3000);
}

// Vulnérabilités:
// - CWE-918: Server-Side Request Forgery (SSRF)
// - CVSS: 8.6 (Haute)
// - CVE: Non spécifique, dépend de l'implémentation
// - Autres référentiels: SANS Top 25 "Server-Side Request Forgery"
// - Outil de test recommandé: DAST pour tester des requêtes SSRF potentielles, SAST pour identifier des entrées non validées

// Fonction souvent identifiée incorrectement comme vulnérable à SSRF (faux positif spécifique à A10)
function A10Negatif() {
    const express = require('express');
    const app = express();

    app.get('/generate-report', (req, res) => {
        // Endpoint qui génère un rapport à partir de données internes sans aucune interaction externe
        const reportData = {
            status: 'Completed',
            message: 'Report generated successfully'
        };

        res.json(reportData);
    });

    app.listen(3000);
}

// Commentaire:
// - Faux positif potentiel: des outils pourraient détecter ce point d'interaction comme un SSRF potentiel,
//   car il est souvent mal interprété que tous les endpoints qui génèrent des données pourraient mener à des accès externes.
// - CWE-918: Server-Side Request Forgery (SSRF) (faux positif)
// - CVSS: Bas, si c'est un faux positif
// - CVE: Non spécifique, dépend de l'interprétation de l'outil
// - Outil de test recommandé: IAST pour surveiller et analyser les flux de données et confirmer l'absence d'interactions serveur à serveur

