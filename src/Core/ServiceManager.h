#pragma once
#include <memory>
#include <unordered_map>
#include <typeindex>
#include <functional>

// Inspired by Dalamud's Service<T> pattern for dependency injection
class ServiceManager {
private:
    static std::unordered_map<std::type_index, std::shared_ptr<void>> s_services;
    static std::unordered_map<std::type_index, std::function<std::shared_ptr<void>()>> s_factories;

public:
    template<typename T>
    static void RegisterService(std::shared_ptr<T> service)
    {
        s_services[std::type_index(typeid(T))] = service;
    }

    template<typename T>
    static void RegisterFactory(std::function<std::shared_ptr<T>()> factory)
    {
        s_factories[std::type_index(typeid(T))] = [factory]() -> std::shared_ptr<void>
            {
                return factory();
            };
    }

    template<typename T>
    static std::shared_ptr<T> Get()
    {
        auto it = s_services.find(std::type_index(typeid(T)));
        if (it != s_services.end())
        {
            return std::static_pointer_cast<T>(it->second);
        }

        // Try to create from factory
        auto factoryIt = s_factories.find(std::type_index(typeid(T)));
        if (factoryIt != s_factories.end())
        {
            auto service = factoryIt->second();
            s_services[std::type_index(typeid(T))] = service;
            return std::static_pointer_cast<T>(service);
        }

        return nullptr;
    }

    template<typename T>
    static bool IsRegistered()
    {
        return s_services.find(std::type_index(typeid(T))) != s_services.end() ||
            s_factories.find(std::type_index(typeid(T))) != s_factories.end();
    }

    static void Clear()
    {
        s_services.clear();
        s_factories.clear();
    }
};

// Usage example inspired by Dalamud's Service<T>.Get() pattern
// auto scanner = ServiceManager::Get<EnhancedPatternScanner>();
// auto database = ServiceManager::Get<FunctionDatabase>();