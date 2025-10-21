#include "SimpleJSON.h"
#include <sstream>
#include <algorithm>
#include <cctype>

namespace SapphireHook {

    // Helpers
    static inline void SkipWS(const std::string& s, size_t& i)
    {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) ++i;
    }

    // NOTE: returns the raw JSON string content (with backslash escapes preserved).
    static bool ParseJSONString(const std::string& s, size_t& i, std::string& out)
    {
        SkipWS(s, i);
        if (i >= s.size() || s[i] != '"') return false;
        ++i; // skip opening "
        std::string raw;
        bool esc = false;
        while (i < s.size())
        {
            char c = s[i++];
            if (esc)
            {
                raw.push_back(c);
                esc = false;
                continue;
            }
            if (c == '\\')
            {
                raw.push_back('\\'); // keep escape marker; unescape in SimpleJSON::Parse
                esc = true;
                continue;
            }
            if (c == '"')
            {
                out = raw; // do not unescape here
                return true;
            }
            raw.push_back(c);
        }
        return false; // unterminated string
    }

    // Extracts a balanced {...} block starting at s[i] == '{', returns substring [i, end)
    static bool ExtractBalancedObject(const std::string& s, size_t& i, std::string& objOut)
    {
        SkipWS(s, i);
        if (i >= s.size() || s[i] != '{') return false;

        size_t start = i;
        int depth = 0;
        bool inStr = false;
        bool esc = false;

        while (i < s.size())
        {
            char c = s[i++];
            if (inStr)
            {
                if (esc) { esc = false; continue; }
                if (c == '\\') { esc = true; continue; }
                if (c == '"') { inStr = false; }
                continue;
            }
            else
            {
                if (c == '"') { inStr = true; continue; }
                if (c == '{') { ++depth; continue; }
                if (c == '}')
                {
                    --depth;
                    if (depth == 0)
                    {
                        objOut = s.substr(start, i - start);
                        return true;
                    }
                }
            }
        }
        return false; // unbalanced braces
    }

    std::string SimpleJSON::Trim(const std::string& str)
    {
        size_t start = str.find_first_not_of(" \t\n\r");
        if (start == std::string::npos) return "";
        size_t end = str.find_last_not_of(" \t\n\r");
        return str.substr(start, end - start + 1);
    }

    std::string SimpleJSON::Unescape(const std::string& str)
    {
        std::string result;
        for (size_t i = 0; i < str.length(); ++i)
        {
            if (str[i] == '\\' && i + 1 < str.length())
            {
                switch (str[i + 1])
                {
                case '"': result += '"'; ++i; break;
                case '\\': result += '\\'; ++i; break;
                case 'n': result += '\n'; ++i; break;
                case 'r': result += '\r'; ++i; break;
                case 't': result += '\t'; ++i; break;
                default: result += str[i]; break;
                }
            }
            else
            {
                result += str[i];
            }
        }
        return result;
    }

    std::string SimpleJSON::Escape(const std::string& str)
    {
        std::string result;
        for (char c : str)
        {
            switch (c)
            {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result += c; break;
            }
        }
        return result;
    }

    SimpleJSON::JSONObject SimpleJSON::Parse(const std::string& jsonString)
    {
        JSONObject result;
        std::string s = Trim(jsonString);
        size_t i = 0;

        if (s.empty() || s[i] != '{') return result;
        ++i; // skip '{'

        while (true)
        {
            SkipWS(s, i);
            if (i >= s.size()) break;
            if (s[i] == '}') { ++i; break; }

            // Key
            std::string keyRaw;
            if (!ParseJSONString(s, i, keyRaw)) break;
            std::string key = Unescape(keyRaw);

            SkipWS(s, i);
            if (i >= s.size() || s[i] != ':') break;
            ++i; // skip ':'

            SkipWS(s, i);
            if (i >= s.size()) break;

            // Value: string or object (we only need these two for our use-cases)
            if (s[i] == '"')
            {
                std::string valRaw;
                if (!ParseJSONString(s, i, valRaw)) break;
                std::string val = Unescape(valRaw);
                result.data[key] = std::move(val);
            }
            else if (s[i] == '{')
            {
                std::string objText;
                if (!ExtractBalancedObject(s, i, objText)) break;

                // Parse nested object
                auto nestedObj = Parse(objText);
                std::map<std::string, std::string> nestedMap;
                for (const auto& pair : nestedObj.data)
                {
                    if (std::holds_alternative<std::string>(pair.second))
                        nestedMap[pair.first] = std::get<std::string>(pair.second);
                }
                result.data[key] = std::move(nestedMap);
            }
            else
            {
                // Fallback: read until ',' or '}' and store as string (e.g., numbers/bools)
                size_t start = i;
                while (i < s.size() && s[i] != ',' && s[i] != '}') ++i;
                std::string raw = Trim(s.substr(start, i - start));
                result.data[key] = raw;
            }

            SkipWS(s, i);
            if (i < s.size() && s[i] == ',') { ++i; continue; }

            SkipWS(s, i);
            if (i < s.size() && s[i] == '}') { ++i; break; }
        }

        return result;
    }

    std::string SimpleJSON::Generate(const JSONObject& obj)
    {
        std::ostringstream ss;
        ss << "{\n";

        bool first = true;
        for (const auto& pair : obj.data)
        {
            if (!first) ss << ",\n";
            first = false;

            ss << "  \"" << Escape(pair.first) << "\": ";

            if (std::holds_alternative<std::string>(pair.second))
            {
                ss << "\"" << Escape(std::get<std::string>(pair.second)) << "\"";
            }
            else if (std::holds_alternative<std::map<std::string, std::string>>(pair.second))
            {
                const auto& nestedMap = std::get<std::map<std::string, std::string>>(pair.second);
                ss << "{\n";
                bool nestedFirst = true;
                for (const auto& nestedPair : nestedMap)
                {
                    if (!nestedFirst) ss << ",\n";
                    nestedFirst = false;
                    ss << "    \"" << Escape(nestedPair.first) << "\": \""
                        << Escape(nestedPair.second) << "\"";
                }
                ss << "\n  }";
            }
        }

        ss << "\n}";
        return ss.str();
    }

} // namespace SapphireHook