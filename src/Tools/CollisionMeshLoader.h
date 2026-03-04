#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <filesystem>
#include <DirectXMath.h>
#include <optional>
#include <functional>
#include <atomic>

namespace SapphireHook::Collision {
	enum class CollisionCategory : uint32_t {
		Unknown = 0,
		BNPC = 1,
		NPC = 2,
		Aetheryte = 3,
		EventObject = 4,
		EventNPC = 5,
		EventRange = 6,
		Marker = 7,
		Pop = 8,
		Notorious = 9,
		BGCommon = 10,
		BGParts = 11,
		Other = 12,

		COUNT = 13
	};

	const char* GetCategoryName(CollisionCategory category);

	DirectX::XMFLOAT4 GetDefaultCategoryColor(CollisionCategory category);

	struct Triangle {
		DirectX::XMFLOAT3 v0;
		DirectX::XMFLOAT3 v1;
		DirectX::XMFLOAT3 v2;
		DirectX::XMFLOAT3 normal;
	};

	struct CollisionObject {
		std::string name;
		CollisionCategory category;
		std::vector<Triangle> triangles;
		DirectX::XMFLOAT3 boundsMin;
		DirectX::XMFLOAT3 boundsMax;
		DirectX::XMFLOAT3 center;
		bool visible = true;

		size_t GetTriangleCount() const { return triangles.size(); }
		void ComputeBounds();
	};

	struct CollisionMesh {
		std::string name;
		std::string sourcePath;
		std::vector<CollisionObject> objects;
		DirectX::XMFLOAT3 worldBoundsMin;
		DirectX::XMFLOAT3 worldBoundsMax;

		size_t totalVertices = 0;
		size_t totalTriangles = 0;
		size_t objectCount = 0;

		std::vector<const CollisionObject*> GetObjectsByCategory(CollisionCategory category) const;

		std::unordered_map<CollisionCategory, size_t> GetCategoryStats() const;
	};

	struct LoadProgress {
		size_t bytesRead = 0;
		size_t totalBytes = 0;
		size_t linesProcessed = 0;
		size_t totalLines = 0;
		size_t verticesLoaded = 0;
		size_t trianglesLoaded = 0;
		size_t objectsLoaded = 0;
		std::string currentObject;
		float percentage = 0.0f;
	};
	using ProgressCallback = std::function<void(const LoadProgress&)>;

	class CollisionMeshLoader {
	public:
		static CollisionMeshLoader& GetInstance();

		std::optional<CollisionMesh> LoadOBJ(const std::filesystem::path& path);

		std::optional<CollisionMesh> LoadOBJ(const std::filesystem::path& path, ProgressCallback callback);

		void LoadOBJAsync(const std::filesystem::path& path,
			std::function<void(std::optional<CollisionMesh>)> onComplete,
			ProgressCallback progressCallback = nullptr);

		void CancelLoad();
		bool IsLoading() const { return m_loading.load(); }

		const std::string& GetLastError() const { return m_lastError; }

	private:
		CollisionMeshLoader() = default;
		~CollisionMeshLoader() = default;
		CollisionMeshLoader(const CollisionMeshLoader&) = delete;
		CollisionMeshLoader& operator=(const CollisionMeshLoader&) = delete;

		CollisionCategory ParseCategory(const std::string& objectName);
		DirectX::XMFLOAT3 ComputeNormal(const DirectX::XMFLOAT3& v0,
			const DirectX::XMFLOAT3& v1,
			const DirectX::XMFLOAT3& v2);

		std::atomic<bool> m_loading{ false };
		std::atomic<bool> m_cancelRequested{ false };
		std::string m_lastError;
	};
}
