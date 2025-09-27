#pragma once
#include <string>
#include <map>
#include <vector>
#include <variant>

namespace SapphireHook {

    class SimpleJSON {
    public:
        using Value = std::variant<std::string, std::map<std::string, std::string>>;

        struct JSONObject {
            std::map<std::string, Value> data;

            bool HasKey(const std::string& key) const
            {
                return data.find(key) != data.end();
            }

            std::string GetString(const std::string& key, const std::string& defaultValue = "") const
            {
                auto it = data.find(key);
                if (it != data.end() && std::holds_alternative<std::string>(it->second))
                {
                    return std::get<std::string>(it->second);
                }
                return defaultValue;
            }

            std::map<std::string, std::string> GetObject(const std::string& key) const
            {
                auto it = data.find(key);
                if (it != data.end() && std::holds_alternative<std::map<std::string, std::string>>(it->second))
                {
                    return std::get<std::map<std::string, std::string>>(it->second);
                }
                return {};
            }
        };

        static JSONObject Parse(const std::string& jsonString);
        static std::string Generate(const JSONObject& obj);

    private:
        static std::string Trim(const std::string& str);
        static std::string Unescape(const std::string& str);
        static std::string Escape(const std::string& str);
    };

}   