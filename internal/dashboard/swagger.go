// Swagger UI handler for serving embedded OpenAPI documentation.
package dashboard

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.yaml
var openapiSpec []byte

// handleSwaggerUI serves the Swagger UI page.
func (s *Server) handleSwaggerUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(swaggerHTML))
}

// handleOpenAPISpec serves the raw OpenAPI specification.
func (s *Server) handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(openapiSpec)
}

const swaggerHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VC Jump API Documentation</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.18.2/swagger-ui.css">
    <style>
        body { margin: 0; padding: 0; background: #1a1a2e; }
        .swagger-ui .topbar { display: none; }
        .swagger-ui { max-width: 1200px; margin: 0 auto; }
        /* Dark theme overrides */
        .swagger-ui .scheme-container { background: #16213e; box-shadow: none; }
        .swagger-ui .opblock-tag { color: #e2e8f0; border-bottom-color: #2d3748; }
        .swagger-ui .opblock-tag:hover { background: rgba(255,255,255,0.05); }
        .swagger-ui .info .title { color: #7dd3fc; }
        .swagger-ui .info p, .swagger-ui .info li { color: #cbd5e1; }
        .swagger-ui .info a { color: #38bdf8; }
        .swagger-ui .btn { border-color: #475569; color: #e2e8f0; }
        .swagger-ui section.models { border-color: #2d3748; }
        .swagger-ui .model-title { color: #7dd3fc; }
        #swagger-header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 24px 32px;
            text-align: center;
            border-bottom: 1px solid #2d3748;
        }
        #swagger-header h1 {
            margin: 0;
            color: #7dd3fc;
            font-family: 'Inter', -apple-system, sans-serif;
            font-size: 1.5rem;
            font-weight: 600;
        }
        #swagger-header p {
            margin: 8px 0 0;
            color: #94a3b8;
            font-family: 'Inter', -apple-system, sans-serif;
            font-size: 0.875rem;
        }
    </style>
</head>
<body>
    <div id="swagger-header">
        <h1>🔐 VC Jump API</h1>
        <p>Interactive API documentation — Try endpoints directly from this page</p>
    </div>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.18.2/swagger-ui-bundle.js"></script>
    <script>
        SwaggerUIBundle({
            url: '/api/docs/openapi.yaml',
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIBundle.SwaggerUIStandalonePreset
            ],
            layout: 'BaseLayout',
            defaultModelsExpandDepth: 1,
            defaultModelExpandDepth: 2,
            docExpansion: 'list',
            filter: true,
            showExtensions: true,
            showCommonExtensions: true,
            tryItOutEnabled: true,
            persistAuthorization: true,
        });
    </script>
</body>
</html>`
