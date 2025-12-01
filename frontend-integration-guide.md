# Frontend Integration Guide for Screenshot API

## 🎨 Two Ways to Display Screenshots

The API now supports two response types for maximum flexibility:

1. **Base64 Data URL** - Embed directly in HTML (best for small images)
2. **File Path** - Serve via static endpoint (best for large images)

## 📡 API Response Types

### Option 1: Base64 Response (Direct Embedding)

**Request:**
```json
POST /screenshot
{
  "url": "https://example.com",
  "response_type": "base64"  // ← Request base64
}
```

**Response:**
```json
{
  "success": true,
  "base64_data": "data:image/jpeg;base64,/9j/4AAQSkZJRg...",
  "size_bytes": 45678,
  "capture_time_ms": 142,
  "url": "https://example.com",
  "response_type": "base64"
}
```

### Option 2: File Path Response (Static Serving)

**Request:**
```json
POST /screenshot
{
  "url": "https://example.com",
  "response_type": "file_path"  // ← Request file path (default)
}
```

**Response:**
```json
{
  "success": true,
  "file_path": "/screenshots/2024-12-01/abc123.jpg",
  "size_bytes": 45678,
  "capture_time_ms": 142,
  "url": "https://example.com",
  "response_type": "file_path"
}
```

**Access the file:**
```
GET http://localhost:8080/screenshots/2024-12-01/abc123.jpg
```

## 🚀 Frontend Examples

### React Component

```jsx
import React, { useState } from 'react';

function ScreenshotCapture() {
  const [url, setUrl] = useState('https://example.com');
  const [screenshot, setScreenshot] = useState(null);
  const [loading, setLoading] = useState(false);
  const [responseType, setResponseType] = useState('base64');

  const captureScreenshot = async () => {
    setLoading(true);
    try {
      const response = await fetch('http://localhost:8080/screenshot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: url,
          response_type: responseType,
          quality: 85,
          width: 1280,
          height: 720
        })
      });

      const data = await response.json();

      if (data.success) {
        setScreenshot(data);
      } else {
        alert(`Error: ${data.error}`);
      }
    } catch (error) {
      alert(`Failed to capture: ${error.message}`);
    }
    setLoading(false);
  };

  return (
    <div>
      <h2>Screenshot Capture</h2>

      <input
        type="url"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="Enter URL"
      />

      <select value={responseType} onChange={(e) => setResponseType(e.target.value)}>
        <option value="base64">Base64 (Direct Embed)</option>
        <option value="file_path">File Path (Static Serve)</option>
      </select>

      <button onClick={captureScreenshot} disabled={loading}>
        {loading ? 'Capturing...' : 'Capture Screenshot'}
      </button>

      {screenshot && screenshot.success && (
        <div>
          <p>Captured in {screenshot.capture_time_ms}ms</p>
          <p>Size: {(screenshot.size_bytes / 1024).toFixed(2)} KB</p>

          {/* Display based on response type */}
          {screenshot.response_type === 'base64' ? (
            <img
              src={screenshot.base64_data}
              alt="Screenshot"
              style={{ maxWidth: '100%' }}
            />
          ) : (
            <img
              src={`http://localhost:8080${screenshot.file_path}`}
              alt="Screenshot"
              style={{ maxWidth: '100%' }}
            />
          )}
        </div>
      )}
    </div>
  );
}

export default ScreenshotCapture;
```

### Vue Component

```vue
<template>
  <div>
    <h2>Screenshot Capture</h2>

    <input v-model="url" type="url" placeholder="Enter URL" />

    <select v-model="responseType">
      <option value="base64">Base64 (Direct Embed)</option>
      <option value="file_path">File Path (Static Serve)</option>
    </select>

    <button @click="captureScreenshot" :disabled="loading">
      {{ loading ? 'Capturing...' : 'Capture Screenshot' }}
    </button>

    <div v-if="screenshot?.success">
      <p>Captured in {{ screenshot.capture_time_ms }}ms</p>
      <p>Size: {{ (screenshot.size_bytes / 1024).toFixed(2) }} KB</p>

      <!-- Display based on response type -->
      <img
        v-if="screenshot.response_type === 'base64'"
        :src="screenshot.base64_data"
        alt="Screenshot"
        style="max-width: 100%"
      />
      <img
        v-else
        :src="`http://localhost:8080${screenshot.file_path}`"
        alt="Screenshot"
        style="max-width: 100%"
      />
    </div>
  </div>
</template>

<script>
import { ref } from 'vue';

export default {
  setup() {
    const url = ref('https://example.com');
    const screenshot = ref(null);
    const loading = ref(false);
    const responseType = ref('base64');

    const captureScreenshot = async () => {
      loading.value = true;
      try {
        const response = await fetch('http://localhost:8080/screenshot', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url: url.value,
            response_type: responseType.value,
            quality: 85,
            width: 1280,
            height: 720
          })
        });

        screenshot.value = await response.json();
      } catch (error) {
        alert(`Failed to capture: ${error.message}`);
      }
      loading.value = false;
    };

    return {
      url,
      screenshot,
      loading,
      responseType,
      captureScreenshot
    };
  }
};
</script>
```

### Vanilla JavaScript

```html
<!DOCTYPE html>
<html>
<head>
  <title>Screenshot Capture</title>
</head>
<body>
  <h2>Screenshot Capture</h2>

  <input type="url" id="url" value="https://example.com" />
  <select id="responseType">
    <option value="base64">Base64</option>
    <option value="file_path">File Path</option>
  </select>
  <button id="capture">Capture</button>

  <div id="result"></div>

  <script>
    document.getElementById('capture').addEventListener('click', async () => {
      const url = document.getElementById('url').value;
      const responseType = document.getElementById('responseType').value;
      const resultDiv = document.getElementById('result');

      resultDiv.innerHTML = 'Loading...';

      try {
        const response = await fetch('http://localhost:8080/screenshot', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url: url,
            response_type: responseType
          })
        });

        const data = await response.json();

        if (data.success) {
          const imgSrc = data.response_type === 'base64'
            ? data.base64_data
            : `http://localhost:8080${data.file_path}`;

          resultDiv.innerHTML = `
            <p>Captured in ${data.capture_time_ms}ms</p>
            <img src="${imgSrc}" style="max-width: 100%;" />
          `;
        } else {
          resultDiv.innerHTML = `Error: ${data.error}`;
        }
      } catch (error) {
        resultDiv.innerHTML = `Error: ${error.message}`;
      }
    });
  </script>
</body>
</html>
```

## 🎯 When to Use Each Approach

### Use Base64 When:
- ✅ Small screenshots (< 200KB)
- ✅ Need immediate display without extra request
- ✅ Embedding in emails or PDFs
- ✅ Offline storage in localStorage
- ✅ No CORS issues to worry about

### Use File Path When:
- ✅ Large screenshots (> 200KB)
- ✅ Need to cache images in browser
- ✅ Want CDN/proxy caching
- ✅ Need direct URL for sharing
- ✅ Performance is critical (smaller JSON response)

## 🔧 Advanced Usage

### Thumbnail Generation

Generate small thumbnails with base64 for gallery view:

```javascript
// Generate thumbnail
const thumbnail = await fetch('/screenshot', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    url: url,
    response_type: 'base64',
    width: 320,
    height: 180,
    quality: 60  // Lower quality for thumbnails
  })
});

// Generate full size
const fullsize = await fetch('/screenshot', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    url: url,
    response_type: 'file_path',
    width: 1920,
    height: 1080,
    quality: 90
  })
});
```

### Progressive Loading

Show base64 thumbnail first, then load full image:

```jsx
function ProgressiveScreenshot({ url }) {
  const [thumbnail, setThumbnail] = useState(null);
  const [fullImage, setFullImage] = useState(null);

  useEffect(() => {
    // Load thumbnail first (base64)
    fetch('/screenshot', {
      method: 'POST',
      body: JSON.stringify({
        url,
        response_type: 'base64',
        width: 160,
        height: 90,
        quality: 50
      })
    })
    .then(res => res.json())
    .then(data => setThumbnail(data.base64_data));

    // Then load full image (file path)
    fetch('/screenshot', {
      method: 'POST',
      body: JSON.stringify({
        url,
        response_type: 'file_path',
        width: 1280,
        height: 720,
        quality: 85
      })
    })
    .then(res => res.json())
    .then(data => setFullImage(`http://localhost:8080${data.file_path}`));
  }, [url]);

  return (
    <div>
      {/* Show thumbnail while loading full image */}
      <img
        src={fullImage || thumbnail}
        style={{
          maxWidth: '100%',
          filter: fullImage ? 'none' : 'blur(5px)'
        }}
      />
    </div>
  );
}
```

### Error Handling

```javascript
async function captureWithRetry(url, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await fetch('/screenshot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, response_type: 'base64' })
      });

      if (response.status === 429) {
        // Queue full, wait and retry
        await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
        continue;
      }

      const data = await response.json();
      if (data.success) return data;

      throw new Error(data.error);
    } catch (error) {
      if (i === maxRetries - 1) throw error;
    }
  }
}
```

## 🔐 CORS Configuration

If your frontend is on a different domain, configure CORS:

```go
// Add to internal/httpapi/server.go
func corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

        if r.Method == "OPTIONS" {
            w.WriteHeader(http.StatusOK)
            return
        }

        next.ServeHTTP(w, r)
    })
}
```

## 📊 Performance Comparison

| Aspect | Base64 | File Path |
|--------|---------|-----------|
| Initial Response Size | Large (33% bigger) | Small (just path) |
| Additional Requests | 0 | 1 (to fetch image) |
| Browser Caching | No | Yes |
| CDN Compatible | No | Yes |
| Best For | Small images, quick display | Large images, reusable |

## 🎬 Live Demo Example

```javascript
// Screenshot comparison tool
class ScreenshotComparison {
  constructor() {
    this.screenshots = [];
  }

  async captureMultiple(urls) {
    const promises = urls.map(url =>
      fetch('/screenshot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url,
          response_type: 'base64',
          width: 640,
          height: 360,
          quality: 70
        })
      }).then(r => r.json())
    );

    this.screenshots = await Promise.all(promises);
    this.display();
  }

  display() {
    const grid = document.getElementById('screenshot-grid');
    grid.innerHTML = this.screenshots.map(s => `
      <div class="screenshot-card">
        <img src="${s.base64_data}" />
        <p>${s.url}</p>
        <small>${s.capture_time_ms}ms</small>
      </div>
    `).join('');
  }
}

// Usage
const comparison = new ScreenshotComparison();
comparison.captureMultiple([
  'https://google.com',
  'https://github.com',
  'https://stackoverflow.com'
]);
```

## 🚀 Production Tips

1. **Use Base64 for**:
   - User avatars
   - Thumbnails
   - Email embeds
   - Quick previews

2. **Use File Path for**:
   - Full-size screenshots
   - Gallery views
   - Downloadable images
   - CDN distribution

3. **Hybrid Approach**:
   - Generate both formats
   - Show base64 immediately
   - Lazy-load file path version

4. **Optimize Requests**:
   ```javascript
   // Batch multiple screenshots
   const screenshots = await Promise.all(
     urls.map(url => captureScreenshot(url))
   );
   ```

5. **Cache Strategy**:
   ```javascript
   // Cache base64 in localStorage
   const cacheKey = `screenshot_${url}`;
   const cached = localStorage.getItem(cacheKey);

   if (cached) {
     return JSON.parse(cached);
   }

   const screenshot = await captureScreenshot(url);
   localStorage.setItem(cacheKey, JSON.stringify(screenshot));
   return screenshot;
   ```