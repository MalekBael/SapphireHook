#include "CollisionMeshLoader.h"
#include "../Logger/Logger.h"
#include <fstream>
#include <sstream>
#include <thread>
#include <algorithm>
#include <cmath>

namespace SapphireHook::Collision {
	const char* GetCategoryName(CollisionCategory category) {
		switch (category) {
		case CollisionCategory::BNPC:        return "BNPC (Battle NPCs)";
		case CollisionCategory::NPC:         return "NPC";
		case CollisionCategory::Aetheryte:   return "Aetheryte";
		case CollisionCategory::EventObject: return "Event Object";
		case CollisionCategory::EventNPC:    return "Event NPC";
		case CollisionCategory::EventRange:  return "Event Range";
		case CollisionCategory::Marker:      return "Marker";
		case CollisionCategory::Pop:         return "Spawn Point";
		case CollisionCategory::Notorious:   return "Notorious Monster";
		case CollisionCategory::BGCommon:    return "BG Common";
		case CollisionCategory::BGParts:     return "BG Parts";
		case CollisionCategory::Other:       return "Other";
		default:                             return "Unknown";
		}
	}

	DirectX::XMFLOAT4 GetDefaultCategoryColor(CollisionCategory category) {
		switch (category) {
		case CollisionCategory::BNPC:        return { 1.0f, 0.3f, 0.3f, 0.6f };  // Red
		case CollisionCategory::NPC:         return { 0.3f, 1.0f, 0.3f, 0.6f };  // Green
		case CollisionCategory::Aetheryte:   return { 0.3f, 0.6f, 1.0f, 0.6f };  // Blue
		case CollisionCategory::EventObject: return { 1.0f, 1.0f, 0.3f, 0.6f };  // Yellow
		case CollisionCategory::EventNPC:    return { 0.6f, 1.0f, 0.6f, 0.6f };  // Light green
		case CollisionCategory::EventRange:  return { 1.0f, 0.6f, 0.0f, 0.6f };  // Orange
		case CollisionCategory::Marker:      return { 1.0f, 0.0f, 1.0f, 0.6f };  // Magenta
		case CollisionCategory::Pop:         return { 0.0f, 1.0f, 1.0f, 0.6f };  // Cyan
		case CollisionCategory::Notorious:   return { 1.0f, 0.0f, 0.5f, 0.6f };  // Pink
		case CollisionCategory::BGCommon:    return { 0.5f, 0.5f, 0.5f, 0.3f };  // Gray (subtle)
		case CollisionCategory::BGParts:     return { 0.6f, 0.6f, 0.6f, 0.3f };  // Light gray
		case CollisionCategory::Other:       return { 0.7f, 0.7f, 0.7f, 0.4f };  // White-ish
		default:                             return { 1.0f, 1.0f, 1.0f, 0.5f };
		}
	}

	// ============================================
	// CollisionObject methods
	// ============================================
	void CollisionObject::ComputeBounds() {
		if (triangles.empty()) {
			boundsMin = boundsMax = center = { 0, 0, 0 };
			return;
		}

		boundsMin = { FLT_MAX, FLT_MAX, FLT_MAX };
		boundsMax = { -FLT_MAX, -FLT_MAX, -FLT_MAX };

		for (const auto& tri : triangles) {
			for (const auto* v : { &tri.v0, &tri.v1, &tri.v2 }) {
				boundsMin.x = (std::min)(boundsMin.x, v->x);
				boundsMin.y = (std::min)(boundsMin.y, v->y);
				boundsMin.z = (std::min)(boundsMin.z, v->z);
				boundsMax.x = (std::max)(boundsMax.x, v->x);
				boundsMax.y = (std::max)(boundsMax.y, v->y);
				boundsMax.z = (std::max)(boundsMax.z, v->z);
			}
		}

		center = {
			(boundsMin.x + boundsMax.x) * 0.5f,
			(boundsMin.y + boundsMax.y) * 0.5f,
			(boundsMin.z + boundsMax.z) * 0.5f
		};
	}

	// ============================================
	// CollisionMesh methods
	// ============================================
	std::vector<const CollisionObject*> CollisionMesh::GetObjectsByCategory(CollisionCategory category) const {
		std::vector<const CollisionObject*> result;
		for (const auto& obj : objects) {
			if (obj.category == category) {
				result.push_back(&obj);
			}
		}
		return result;
	}

	std::unordered_map<CollisionCategory, size_t> CollisionMesh::GetCategoryStats() const {
		std::unordered_map<CollisionCategory, size_t> stats;
		for (const auto& obj : objects) {
			stats[obj.category] += obj.triangles.size();
		}
		return stats;
	}

	// ============================================
	// CollisionMeshLoader implementation
	// ============================================
	CollisionMeshLoader& CollisionMeshLoader::GetInstance() {
		static CollisionMeshLoader instance;
		return instance;
	}

	CollisionCategory CollisionMeshLoader::ParseCategory(const std::string& name) {
		if (name.find("LVD_BNPC") != std::string::npos) return CollisionCategory::BNPC;
		if (name.find("LVD_NM") != std::string::npos) return CollisionCategory::Notorious;
		if (name.find("LVD_ENPC") != std::string::npos) return CollisionCategory::EventNPC;
		if (name.find("LVD_NPC") != std::string::npos) return CollisionCategory::NPC;
		if (name.find("LVD_aetheryte") != std::string::npos) return CollisionCategory::Aetheryte;
		if (name.find("LVD_EO") != std::string::npos) return CollisionCategory::EventObject;
		if (name.find("LVD_ER") != std::string::npos) return CollisionCategory::EventRange;
		if (name.find("LVD_Marker") != std::string::npos) return CollisionCategory::Marker;
		if (name.find("LVD_pop") != std::string::npos) return CollisionCategory::Pop;
		if (name.find("bgcommon") != std::string::npos) return CollisionCategory::BGCommon;
		if (name.find("bg/") != std::string::npos) return CollisionCategory::BGParts;
		if (name.starts_with("BG_")) return CollisionCategory::BGParts;
		if (name.starts_with("E") && name.find("_") != std::string::npos) return CollisionCategory::Other;

		return CollisionCategory::Other;
	}

	DirectX::XMFLOAT3 CollisionMeshLoader::ComputeNormal(
		const DirectX::XMFLOAT3& v0,
		const DirectX::XMFLOAT3& v1,
		const DirectX::XMFLOAT3& v2)
	{
		DirectX::XMFLOAT3 e1 = { v1.x - v0.x, v1.y - v0.y, v1.z - v0.z };
		DirectX::XMFLOAT3 e2 = { v2.x - v0.x, v2.y - v0.y, v2.z - v0.z };

		DirectX::XMFLOAT3 n = {
			e1.y * e2.z - e1.z * e2.y,
			e1.z * e2.x - e1.x * e2.z,
			e1.x * e2.y - e1.y * e2.x
		};

		float len = std::sqrt(n.x * n.x + n.y * n.y + n.z * n.z);
		if (len > 0.0001f) {
			n.x /= len;
			n.y /= len;
			n.z /= len;
		}

		return n;
	}

	std::optional<CollisionMesh> CollisionMeshLoader::LoadOBJ(const std::filesystem::path& path) {
		return LoadOBJ(path, nullptr);
	}

	std::optional<CollisionMesh> CollisionMeshLoader::LoadOBJ(
		const std::filesystem::path& path,
		ProgressCallback callback)
	{
		m_loading = true;
		m_cancelRequested = false;
		m_lastError.clear();

		if (!std::filesystem::exists(path)) {
			m_lastError = "File not found: " + path.string();
			LogError("[CollisionMeshLoader] " + m_lastError);
			m_loading = false;
			return std::nullopt;
		}

		size_t fileSize = std::filesystem::file_size(path);

		std::ifstream file(path);
		if (!file.is_open()) {
			m_lastError = "Failed to open file: " + path.string();
			LogError("[CollisionMeshLoader] " + m_lastError);
			m_loading = false;
			return std::nullopt;
		}

		CollisionMesh mesh;
		mesh.name = path.filename().string();
		mesh.sourcePath = path.string();
		mesh.worldBoundsMin = { FLT_MAX, FLT_MAX, FLT_MAX };
		mesh.worldBoundsMax = { -FLT_MAX, -FLT_MAX, -FLT_MAX };

		std::vector<DirectX::XMFLOAT3> vertices;
		vertices.reserve(100000);

		CollisionObject* currentObject = nullptr;
		std::string currentObjectName;

		LoadProgress progress;
		progress.totalBytes = fileSize;

		std::string line;
		size_t lineCount = 0;
		size_t bytesRead = 0;

		while (std::getline(file, line)) {
			if (m_cancelRequested) {
				m_lastError = "Load cancelled";
				m_loading = false;
				return std::nullopt;
			}

			bytesRead += line.size() + 1;
			lineCount++;

			if (line.empty() || line[0] == '#') continue;

			std::istringstream iss(line);
			std::string prefix;
			iss >> prefix;

			if (prefix == "o" || prefix == "g") {
				std::string name;
				std::getline(iss >> std::ws, name);

				if (!name.empty() && name != currentObjectName) {
					if (currentObject && !currentObject->triangles.empty()) {
						currentObject->ComputeBounds();
					}

					mesh.objects.emplace_back();
					currentObject = &mesh.objects.back();
					currentObject->name = name;
					currentObject->category = ParseCategory(name);
					currentObjectName = name;

					progress.currentObject = name;
					progress.objectsLoaded = mesh.objects.size();
				}
			}
			else if (prefix == "v") {
				// Vertex
				float x, y, z;
				iss >> x >> y >> z;
				vertices.push_back({ x, y, z });
				mesh.totalVertices++;

				// Update world bounds
				mesh.worldBoundsMin.x = (std::min)(mesh.worldBoundsMin.x, x);
				mesh.worldBoundsMin.y = (std::min)(mesh.worldBoundsMin.y, y);
				mesh.worldBoundsMin.z = (std::min)(mesh.worldBoundsMin.z, z);
				mesh.worldBoundsMax.x = (std::max)(mesh.worldBoundsMax.x, x);
				mesh.worldBoundsMax.y = (std::max)(mesh.worldBoundsMax.y, y);
				mesh.worldBoundsMax.z = (std::max)(mesh.worldBoundsMax.z, z);

				progress.verticesLoaded = mesh.totalVertices;
			}
			else if (prefix == "f") {
				// Face - can have 3 or more vertices (we triangulate)
				if (!currentObject) {
					// Create default object if none defined
					mesh.objects.emplace_back();
					currentObject = &mesh.objects.back();
					currentObject->name = "default";
					currentObject->category = CollisionCategory::Other;
				}

				std::vector<int> indices;
				std::string token;
				while (iss >> token) {
					// Parse vertex index (handle v, v/vt, v/vt/vn, v//vn formats)
					int idx = 0;
					size_t slashPos = token.find('/');
					if (slashPos != std::string::npos) {
						idx = std::stoi(token.substr(0, slashPos));
					}
					else {
						idx = std::stoi(token);
					}

					if (idx < 0) {
						idx = static_cast<int>(vertices.size()) + idx;
					}
					else {
						idx--;
					}

					if (idx >= 0 && idx < static_cast<int>(vertices.size())) {
						indices.push_back(idx);
					}
				}

				if (indices.size() >= 3) {
					for (size_t i = 1; i + 1 < indices.size(); i++) {
						Triangle tri;
						tri.v0 = vertices[indices[0]];
						tri.v1 = vertices[indices[i]];
						tri.v2 = vertices[indices[i + 1]];
						tri.normal = ComputeNormal(tri.v0, tri.v1, tri.v2);
						currentObject->triangles.push_back(tri);
						mesh.totalTriangles++;
					}
					progress.trianglesLoaded = mesh.totalTriangles;
				}
			}

			if (callback && (lineCount % 10000 == 0)) {
				progress.bytesRead = bytesRead;
				progress.linesProcessed = lineCount;
				if (bytesRead > 0) {
					progress.totalLines = static_cast<size_t>(
						static_cast<double>(lineCount) / bytesRead * fileSize);
				}
				progress.percentage = static_cast<float>(bytesRead) / fileSize * 100.0f;
				callback(progress);
			}
		}

		if (currentObject && !currentObject->triangles.empty()) {
			currentObject->ComputeBounds();
		}

		mesh.objects.erase(
			std::remove_if(mesh.objects.begin(), mesh.objects.end(),
				[](const CollisionObject& obj) { return obj.triangles.empty(); }),
			mesh.objects.end());

		mesh.objectCount = mesh.objects.size();

		if (callback) {
			progress.bytesRead = fileSize;
			progress.percentage = 100.0f;
			callback(progress);
		}

		LogInfo("[CollisionMeshLoader] Loaded " + path.filename().string() +
			": " + std::to_string(mesh.objectCount) + " objects, " +
			std::to_string(mesh.totalVertices) + " vertices, " +
			std::to_string(mesh.totalTriangles) + " triangles");

		m_loading = false;
		return mesh;
	}

	void CollisionMeshLoader::LoadOBJAsync(
		const std::filesystem::path& path,
		std::function<void(std::optional<CollisionMesh>)> onComplete,
		ProgressCallback progressCallback)
	{
		std::thread([this, path, onComplete, progressCallback]() {
			auto result = LoadOBJ(path, progressCallback);
			if (onComplete) {
				onComplete(std::move(result));
			}
			}).detach();
	}

	void CollisionMeshLoader::CancelLoad() {
		m_cancelRequested = true;
	}
} // namespace SapphireHook::Collision