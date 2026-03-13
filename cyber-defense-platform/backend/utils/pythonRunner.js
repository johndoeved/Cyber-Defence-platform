const { PythonShell } = require('python-shell');
const path = require('path');

class PythonRunner {
    /**
     * Run a Python script with arguments
     * @param {string} scriptPath - Path to the Python script
     * @param {Array} args - Command line arguments
     * @param {string} input - Optional stdin input
     * @returns {Promise<object>} Parsed JSON output from the script
     */
    static async runScript(scriptPath, args = [], input = null) {
        return new Promise((resolve, reject) => {
            const options = {
                mode: 'json',
                pythonPath: 'python',
                pythonOptions: ['-u'],
                scriptPath: path.dirname(scriptPath),
                args: args
            };

            if (input) {
                options.mode = 'text';
            }

            const shell = new PythonShell(path.basename(scriptPath), options);
            let results = [];

            // Add timeout
            const timeout = setTimeout(() => {
                shell.terminate();
                reject(new Error(`Python script execution timed out after 12.5s: ${scriptPath}`));
            }, 12500);


            if (input) {
                shell.send(input);
            }

            shell.on('message', (message) => {
                results.push(message);
            });

            shell.on('error', (err) => {
                clearTimeout(timeout);
                console.error(`Python script error (${scriptPath}):`, err);
                reject(err);
            });

            shell.end((err) => {
                clearTimeout(timeout);
                if (err) {

                    console.error(`Python script execution failed (${scriptPath}):`, err);
                    reject(err);
                } else {
                    try {
                        if (results.length === 1) {
                            resolve(typeof results[0] === 'string' ? JSON.parse(results[0]) : results[0]);
                        } else if (results.length > 1) {
                            const lastResult = results[results.length - 1];
                            resolve(typeof lastResult === 'string' ? JSON.parse(lastResult) : lastResult);
                        } else {
                            resolve({ success: false, error: 'No output from Python script', details: 'Check if script prints JSON to stdout' });
                        }
                    } catch (parseError) {
                        console.error('Failed to parse Python output:', results.join('\n'));
                        resolve({ raw: results.join('\n'), parseError: true });
                    }
                }
            });
        });
    }

    /**
     * Run a Python script with JSON input via stdin
     * @param {string} scriptPath - Path to the Python script
     * @param {object} inputData - Data to send as JSON via stdin
     * @returns {Promise<object>} Parsed JSON output from the script
     */
    static async runWithStdin(scriptPath, inputData) {
        return new Promise((resolve, reject) => {
            const options = {
                mode: 'text',
                pythonPath: 'python',
                pythonOptions: ['-u'],
                scriptPath: path.dirname(scriptPath)
            };

            const shell = new PythonShell(path.basename(scriptPath), options);
            let output = '';

            // Add timeout
            const timeout = setTimeout(() => {
                shell.terminate();
                reject(new Error(`Python script execution timed out after 12.5s: ${scriptPath}`));
            }, 12500);


            shell.send(JSON.stringify(inputData));

            shell.on('message', (message) => {
                output += message;
            });

            shell.on('error', (err) => {
                clearTimeout(timeout);
                console.error(`Python script error (${scriptPath}):`, err);
                reject(err);
            });

            shell.end((err) => {
                clearTimeout(timeout);
                if (err) {
                    console.error(`Python script execution failed (${scriptPath}):`, err);
                    reject(err);
                } else {
                    try {
                        resolve(JSON.parse(output));
                    } catch (parseError) {
                        console.error('Failed to parse Python output:', output);
                        resolve({ raw: output, parseError: true });
                    }
                }
            });
        });
    }
}

module.exports = PythonRunner;
