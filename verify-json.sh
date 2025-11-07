#!/bin/bash
echo "🔍 Verifying JSON files..."
if node -e "require('./package.json')" 2>/dev/null; then
    echo "✅ package.json is valid"
else
    echo "❌ package.json is invalid"
    exit 1
fi

if node -e "require('./railway.json')" 2>/dev/null; then
    echo "✅ railway.json is valid"
else
    echo "❌ railway.json is invalid"
    exit 1
fi

echo "🎉 All JSON files are valid!"
