const fs = require('fs');
const path = require('path');

const filePath = path.join(__dirname, 'node_modules', 'playwright-core', 'lib', 'coreBundle.js');

if (fs.existsSync(filePath)) {
    let content = fs.readFileSync(filePath, 'utf8');
    
    const targetBlock = `            location: {
              url: pageError.location.url,
              line: pageError.location.lineNumber,
              column: pageError.location.columnNumber
            }`;
            
    const safeBlock = `            location: {
              url: pageError.location ? pageError.location.url : "",
              line: pageError.location ? pageError.location.lineNumber : 0,
              column: pageError.location ? pageError.location.columnNumber : 0
            }`;
            
    if (content.includes(targetBlock)) {
        content = content.replace(targetBlock, safeBlock);
        fs.writeFileSync(filePath, content, 'utf8');
        console.log('[Patch] Successfully patched playwright-core crash bug.');
    } else {
        console.log('[Patch] Target block not found. Maybe already patched or different version.');
    }
} else {
    console.log('[Patch] playwright-core not found at ' + filePath);
}
