#include "TouchID.h"
#include <LocalAuthentication/LocalAuthentication.h>

bool TouchID::saveKey(const QString& database_path, Key* key)
{
    CFErrorRef error = NULL;
    
    SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(NULL,
                                                                    kSecAttrAccessibleAlwaysThisDeviceOnly,
                                                                    kSecAccessControlTouchIDAny, &error);
	
												
    if (sacObject == NULL || error != NULL) 
        return false;
              
    CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	
    QByteArray rawKey = key->rawKey();
    CFDataRef valueData = CFDataCreateWithBytesNoCopy(NULL, reinterpret_cast<UInt8*>(rawKey.data()), rawKey.length(), NULL);
    CFDictionarySetValue(attributes, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(attributes, kSecAttrAccount, database_path.toNSString());
    CFDictionarySetValue(attributes, kSecValueData, valueData);
    CFDictionarySetValue(attributes, kSecUseAuthenticationUI, kSecUseAuthenticationUIAllow);
    CFDictionarySetValue(attributes, kSecAttrAccessControl, sacObject);  
    OSStatus status =  SecItemAdd(attributes, NULL);
    CFRelease(sacObject);
    CFRelease(attributes);
    return status == errSecSuccess;
}

TouchIDKey* TouchID::getKey(const QString& database_path)
{
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrAccount, database_path.toNSString());
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue  );
    CFDictionarySetValue(query, kSecUseOperationPrompt, CFSTR("Authenticate to access KeepassXC"));
	
    CFTypeRef dataTypeRef = NULL;
    OSStatus status = SecItemCopyMatching(query, &dataTypeRef);  
    CFRelease(query);
    if (status == errSecSuccess && dataTypeRef != NULL)
        return new TouchIDKey(static_cast<CFDataRef>(dataTypeRef));
    else
        return NULL; 
}

bool TouchID::isAvailable()
{
    LAContext* context = [[LAContext alloc] init];
    bool available = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:nil];
	CFRelease(context);
	return available;
}

TouchIDKey::TouchIDKey()
{
}

TouchIDKey::TouchIDKey(CFDataRef key)
{
    m_key = QByteArray(reinterpret_cast<const char*>(CFDataGetBytePtr(key)), CFDataGetLength(key));
    CFRelease(key);
}

QByteArray TouchIDKey::rawKey() const
{
    return m_key;
}

TouchIDKey* TouchIDKey::clone() const
{
    return new TouchIDKey(*this);
}
