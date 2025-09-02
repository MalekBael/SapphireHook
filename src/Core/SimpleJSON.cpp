#include "SimpleJSON.h"
#include <sstream>
#include <algorithm>

namespace SapphireHook {

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
        std::string content = Trim(jsonString);

        if (content.empty() || content[0] != '{')
        {
            return result;
        }

        // Simple state machine for parsing
        size_t pos = 1; // Skip opening brace
        std::string currentKey;
        std::string currentValue;
        bool inString = false;
        bool inKey = true;
        bool escapeNext = false;
        int braceLevel = 0;

        while (pos < content.length() && content[pos] != '}')
        {
            char c = content[pos];

            if (escapeNext)
            {
                if (inKey) currentKey += c;
                else currentValue += c;
                escapeNext = false;
                pos++;
                continue;
            }

            if (c == '\\')
            {
                escapeNext = true;
                pos++;
                continue;
            }

            if (c == '"')
            {
                inString = !inString;
                pos++;
                continue;
            }

            if (!inString)
            {
                if (c == ':' && inKey)
                {
                    inKey = false;
                    currentKey = Trim(currentKey);
                    pos++;
                    continue;
                }

                if (c == '{')
                {
                    braceLevel++;
                }
                else if (c == '}')
                {
                    braceLevel--;
                }

                if ((c == ',' || pos == content.length() - 1) && braceLevel == 0)
                {
                    currentValue = Trim(currentValue);

                    if (!currentKey.empty())
                    {
                        if (currentValue.front() == '{' && currentValue.back() == '}')
                        {
                            // Parse nested object
                            auto nestedObj = Parse(currentValue);
                            std::map<std::string, std::string> nestedMap;
                            for (const auto& pair : nestedObj.data)
                            {
                                if (std::holds_alternative<std::string>(pair.second))
                                {
                                    nestedMap[pair.first] = std::get<std::string>(pair.second);
                                }
                            }
                            result.data[currentKey] = nestedMap;
                        }
                        else
                        {
                            // Remove quotes if present
                            if (currentValue.length() >= 2 &&
                                currentValue.front() == '"' && currentValue.back() == '"')
                            {
                                currentValue = currentValue.substr(1, currentValue.length() - 2);
                            }
                            result.data[currentKey] = Unescape(currentValue);
                        }
                    }

                    currentKey.clear();
                    currentValue.clear();
                    inKey = true;
                    pos++;
                    continue;
                }

                if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
                {
                    if (inKey) currentKey += c;
                    else currentValue += c;
                }
            }
            else
            {
                if (inKey) currentKey += c;
                else currentValue += c;
            }

            pos++;
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