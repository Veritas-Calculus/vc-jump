package dashboard

import (
	"net/http"
	"strconv"
)

const (
	defaultPageSize = 20
	maxPageSize     = 100
)

// PaginatedResponse wraps a list response with pagination metadata.
type PaginatedResponse struct {
	Data     interface{} `json:"data"`
	Total    int         `json:"total"`
	Page     int         `json:"page"`
	PageSize int         `json:"page_size"`
	Pages    int         `json:"pages"`
}

// PaginationParams holds parsed pagination query parameters.
type PaginationParams struct {
	Page     int
	PageSize int
	Offset   int
}

// parsePagination extracts page and page_size from query parameters.
// Returns nil if no pagination params are present (backward-compatible: return raw array).
func parsePagination(r *http.Request) *PaginationParams {
	pageStr := r.URL.Query().Get("page")
	if pageStr == "" {
		return nil // No pagination requested — caller should return raw array.
	}

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	pageSize := defaultPageSize
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 {
			pageSize = v
		}
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}

	return &PaginationParams{
		Page:     page,
		PageSize: pageSize,
		Offset:   (page - 1) * pageSize,
	}
}

// newPaginatedResponse creates a PaginatedResponse envelope.
func newPaginatedResponse(data interface{}, total int, p *PaginationParams) PaginatedResponse {
	pages := total / p.PageSize
	if total%p.PageSize != 0 {
		pages++
	}
	if pages < 1 {
		pages = 1
	}
	return PaginatedResponse{
		Data:     data,
		Total:    total,
		Page:     p.Page,
		PageSize: p.PageSize,
		Pages:    pages,
	}
}
