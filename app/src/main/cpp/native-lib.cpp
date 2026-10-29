#include <jni.h>
#include <node.h>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static std::string javaString(JNIEnv* env, jstring value) {
    if (value == nullptr) return {};
    const char* chars = env->GetStringUTFChars(value, nullptr);
    if (chars == nullptr) return {};
    std::string result(chars);
    env->ReleaseStringUTFChars(value, chars);
    return result;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_roarnet_app_MainActivity_startNode(
    JNIEnv* env,
    jobject,
    jstring scriptPath,
    jstring databasePath,
    jstring adminToken
) {
    const std::string script = javaString(env, scriptPath);
    const std::string database = javaString(env, databasePath);
    const std::string token = javaString(env, adminToken);

    if (script.empty() || database.empty() || token.size() < 32) {
        return -1;
    }

    if (setenv("DB_PATH", database.c_str(), 1) != 0 ||
        setenv("NODE_ENV", "production", 1) != 0 ||
        setenv("HOST", "127.0.0.1", 1) != 0 ||
        setenv("PORT", "3180", 1) != 0 ||
        setenv("ADMIN_TOKEN", token.c_str(), 1) != 0) {
        return -2;
    }

    std::vector<std::string> storage = {"node", script};
    std::vector<char*> argv;
    argv.reserve(storage.size());

    for (auto& item : storage) {
        argv.push_back(item.data());
    }

    return node::Start(static_cast<int>(argv.size()), argv.data());
}
