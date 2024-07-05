import express from 'express';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import fs from 'fs';
import { exec, execSync } from 'child_process';
import path from 'path';
import { WebSocketServer } from 'ws';

const app = express();
const __dirname = path.resolve();
const hashcatPath = 'C:\\hashcat-6.2.3';
const hashFilePath = path.join(hashcatPath, 'hash.txt');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let hashcatProcess = null;
let currentStatus = {
    message: '',
    device: '',
    status: '',
    timeStarted: '',
    timeEstimated: '',
    guessMask: '',
    speed: ''
};

const wss = new WebSocketServer({ port: 8080 });

wss.on('connection', (ws) => {
    ws.on('message', async (message) => {
        const { password, mask, algorithm, action } = JSON.parse(message);

        if (action === 'start') {
            let hash = '';
            let hashcatMode = '';

            // Hash the password and set the appropriate Hashcat mode
            switch (algorithm) {
                case 'md5':
                    hash = crypto.createHash('md5').update(password).digest('hex');
                    hashcatMode = '0';
                    break;
                case 'sha256':
                    hash = crypto.createHash('sha256').update(password).digest('hex');
                    hashcatMode = '1400';
                    break;
                case 'bcrypt':
                    hash = await bcrypt.hash(password, 10);
                    hashcatMode = '3200';
                    break;
                default:
                    ws.send(JSON.stringify({ message: 'Unsupported algorithm', done: true }));
                    return;
            }

            // Ensure bcrypt hash is written correctly
            fs.writeFileSync(hashFilePath, `${hash}\n`);

            const hashcatCommand = `${hashcatPath}\\hashcat.exe -m ${hashcatMode} -a 3 -O ${hashFilePath} ${mask} --backend-devices=1 --status --status-timer=1`;
            hashcatProcess = exec(hashcatCommand, { cwd: hashcatPath });

            hashcatProcess.stdout.on('data', (data) => {
                const lines = data.toString().split('\n');
                for (let line of lines) {
                    line = line.trim();
                    //console.log('Processing line:', line);
                    updateStatus(line, currentStatus, algorithm);
                    ws.send(JSON.stringify(currentStatus));
                }
            });

            hashcatProcess.stderr.on('data', (data) => {
                console.error('Hashcat stderr:', data.toString());
            });

            hashcatProcess.on('exit', (code) => {
                console.log(`Hashcat process exited with code ${code}`);
                ws.send(JSON.stringify({ done: true }));
            });
        } else if (action === 'stop') {
            if (hashcatProcess) {
                try {
                    execSync(`taskkill /pid ${hashcatProcess.pid} /f /t`);
                } catch (error) {
                    console.error('Failed to kill hashcat process:', error);
                }
                ws.send(JSON.stringify(currentStatus));
                hashcatProcess = null;
            }
        }
    });
});

function updateStatus(line, status, algorithm) {
    let passwordMatch;
    
    if (algorithm === 'bcrypt') {
        passwordMatch = line.match(/(\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}):(.*)/);
    } else {
        passwordMatch = line.match(/([a-f0-9]{32}):(.+)/);
    }

    if (passwordMatch) {
        status.message = `Password cracked: ${passwordMatch[2]}`;
    }

    // Extract other details
    if (line.startsWith('Status...........:')) {
        status.status = line.split('Status...........:')[1].trim();
    } else if (line.startsWith('Time.Started.....:')) {
        status.timeStarted = line.split('Time.Started.....:')[1].trim();
    } else if (line.startsWith('Time.Estimated...:')) {
        status.timeEstimated = line.split('Time.Estimated...:')[1].trim();
    } else if (line.startsWith('Guess.Mask.......:')) {
        status.guessMask = line.split('Guess.Mask.......:')[1].trim();
    } else if (line.startsWith('Speed.#1.........:')) {
        status.speed = line.split('Speed.#1.........:')[1].trim();
    }else if (line.startsWith('* Device #1:')) {
        status.device = line.split('* Device #1:')[1].trim();
    }
}

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
