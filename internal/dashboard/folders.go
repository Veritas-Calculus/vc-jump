package dashboard

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Veritas-Calculus/vc-jump/internal/storage"
)

// handleFolders handles folder list and creation.
func (s *Server) handleFolders(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listFolders(w, r)
	case http.MethodPost:
		s.createFolder(w, r)
	default:
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFolder handles individual folder operations.
func (s *Server) handleFolder(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/folders/")
	if id == "" {
		s.jsonError(w, "folder ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getFolder(w, r, id)
	case http.MethodPut:
		s.updateFolder(w, r, id)
	case http.MethodDelete:
		s.deleteFolder(w, r, id)
	default:
		s.jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) listFolders(w http.ResponseWriter, r *http.Request) {
	if !s.hasPermission(r, "host:view") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	// Check if requesting tree structure
	if r.URL.Query().Get("tree") == "true" {
		s.getFolderTree(w, r)
		return
	}

	folders, err := s.store.ListFolders(r.Context())
	if err != nil {
		s.jsonError(w, "failed to list folders", http.StatusInternalServerError)
		return
	}
	if folders == nil {
		folders = []storage.Folder{}
	}
	s.jsonResponse(w, folders)
}

// FolderNode represents a folder in the tree structure with children.
type FolderNode struct {
	storage.Folder
	Children []FolderNode   `json:"children"`
	Hosts    []storage.Host `json:"hosts,omitempty"`
}

func (s *Server) getFolderTree(w http.ResponseWriter, r *http.Request) {
	folders, err := s.store.ListFolders(r.Context())
	if err != nil {
		s.jsonError(w, "failed to list folders", http.StatusInternalServerError)
		return
	}

	hosts, err := s.store.ListHosts(r.Context())
	if err != nil {
		s.jsonError(w, "failed to list hosts", http.StatusInternalServerError)
		return
	}

	folderMap := s.buildFolderMap(folders)
	hostsByFolder, rootHosts := s.groupHostsByFolder(hosts)
	s.assignHostsToFolders(folderMap, hostsByFolder)
	rootFolders := s.buildFolderHierarchy(folders, folderMap)

	s.jsonResponse(w, map[string]interface{}{
		"folders": rootFolders,
		"hosts":   rootHosts,
	})
}

// buildFolderMap creates a map of folder ID to FolderNode.
func (s *Server) buildFolderMap(folders []storage.Folder) map[string]*FolderNode {
	folderMap := make(map[string]*FolderNode)
	for _, f := range folders {
		folderMap[f.ID] = &FolderNode{Folder: f, Children: []FolderNode{}}
	}
	return folderMap
}

// groupHostsByFolder separates hosts into folder-grouped and root-level hosts.
func (s *Server) groupHostsByFolder(hosts []storage.Host) (map[string][]storage.Host, []storage.Host) {
	hostsByFolder := make(map[string][]storage.Host)
	var rootHosts []storage.Host
	for _, h := range hosts {
		if h.FolderID == "" {
			rootHosts = append(rootHosts, h)
		} else {
			hostsByFolder[h.FolderID] = append(hostsByFolder[h.FolderID], h)
		}
	}
	if rootHosts == nil {
		rootHosts = []storage.Host{}
	}
	return hostsByFolder, rootHosts
}

// assignHostsToFolders assigns hosts to their respective folder nodes.
func (s *Server) assignHostsToFolders(folderMap map[string]*FolderNode, hostsByFolder map[string][]storage.Host) {
	for id, node := range folderMap {
		node.Hosts = hostsByFolder[id]
		if node.Hosts == nil {
			node.Hosts = []storage.Host{}
		}
	}
}

// buildFolderHierarchy builds the folder tree structure recursively.
func (s *Server) buildFolderHierarchy(folders []storage.Folder, folderMap map[string]*FolderNode) []FolderNode {
	var buildTree func(node *FolderNode)
	buildTree = func(node *FolderNode) {
		var children []FolderNode
		for _, f := range folders {
			if f.ParentID == node.ID {
				child := folderMap[f.ID]
				buildTree(child)
				children = append(children, *child)
			}
		}
		if children == nil {
			children = []FolderNode{}
		}
		node.Children = children
	}

	var rootFolders []FolderNode
	for _, f := range folders {
		if f.ParentID == "" {
			node := folderMap[f.ID]
			buildTree(node)
			rootFolders = append(rootFolders, *node)
		}
	}
	if rootFolders == nil {
		rootFolders = []FolderNode{}
	}
	return rootFolders
}

func (s *Server) createFolder(w http.ResponseWriter, r *http.Request) {
	if !s.hasPermission(r, "host:create") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	var req struct {
		Name        string `json:"name"`
		ParentID    string `json:"parent_id"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		s.jsonError(w, "name is required", http.StatusBadRequest)
		return
	}

	// Build path
	path := "/" + req.Name
	if req.ParentID != "" {
		parent, err := s.store.GetFolder(r.Context(), req.ParentID)
		if err != nil || parent == nil {
			s.jsonError(w, "parent folder not found", http.StatusBadRequest)
			return
		}
		path = parent.Path + "/" + req.Name
	}

	folder := storage.Folder{
		ID:          generateID(),
		Name:        req.Name,
		ParentID:    req.ParentID,
		Path:        path,
		Description: req.Description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.store.CreateFolder(r.Context(), folder); err != nil {
		s.jsonError(w, "failed to create folder: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, folder)
}

func (s *Server) getFolder(w http.ResponseWriter, r *http.Request, id string) {
	if !s.hasPermission(r, "host:view") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	folder, err := s.store.GetFolder(r.Context(), id)
	if err != nil || folder == nil {
		s.jsonError(w, "folder not found", http.StatusNotFound)
		return
	}

	// Get subfolders and hosts
	subfolders, _ := s.store.ListSubfolders(r.Context(), id)
	hosts, _ := s.store.ListHostsByFolder(r.Context(), id)

	if subfolders == nil {
		subfolders = []storage.Folder{}
	}
	if hosts == nil {
		hosts = []storage.Host{}
	}

	s.jsonResponse(w, map[string]interface{}{
		"folder":     folder,
		"subfolders": subfolders,
		"hosts":      hosts,
	})
}

func (s *Server) updateFolder(w http.ResponseWriter, r *http.Request, id string) {
	if !s.hasPermission(r, "host:update") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	existing, err := s.store.GetFolder(r.Context(), id)
	if err != nil || existing == nil {
		s.jsonError(w, "folder not found", http.StatusNotFound)
		return
	}

	var req struct {
		Name        string `json:"name"`
		ParentID    string `json:"parent_id"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Prevent circular reference
	if req.ParentID == id {
		s.jsonError(w, "folder cannot be its own parent", http.StatusBadRequest)
		return
	}

	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.ParentID != existing.ParentID {
		existing.ParentID = req.ParentID
		// Rebuild path
		if req.ParentID == "" {
			existing.Path = "/" + existing.Name
		} else {
			parent, err := s.store.GetFolder(r.Context(), req.ParentID)
			if err != nil || parent == nil {
				s.jsonError(w, "parent folder not found", http.StatusBadRequest)
				return
			}
			existing.Path = parent.Path + "/" + existing.Name
		}
	}
	if req.Description != "" {
		existing.Description = req.Description
	}

	if err := s.store.UpdateFolder(r.Context(), *existing); err != nil {
		s.jsonError(w, "failed to update folder: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, existing)
}

func (s *Server) deleteFolder(w http.ResponseWriter, r *http.Request, id string) {
	if !s.hasPermission(r, "host:delete") {
		s.jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	if err := s.store.DeleteFolder(r.Context(), id); err != nil {
		s.jsonError(w, "failed to delete folder: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]string{"status": "deleted"})
}

// generateID for folders (use the same pattern as elsewhere)
func generateID() string {
	return generateSnowflakeID()
}

func generateSnowflakeID() string {
	// Simple ID generation - in production use a proper snowflake library
	return time.Now().Format("20060102150405") + randomString(6)
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
		time.Sleep(time.Nanosecond)
	}
	return string(b)
}
