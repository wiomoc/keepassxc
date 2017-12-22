#ifndef KEEPASSX_TOUCHID_H
#define KEEPASSX_TOUCHID_H

#include <QByteArray>
#include <QString>
#include "Key.h"
#include "CompositeKey.h"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

class TouchIDKey : public CompositeKey 
{
private:
    QByteArray m_key;
public:
    TouchIDKey();
    explicit TouchIDKey(CFDataRef key);
    QByteArray rawKey() const;
    TouchIDKey* clone() const;
};


class TouchID
{
public:
	static bool isAvailable();
    static bool saveKey(const QString& database_path, Key* key); 
    static TouchIDKey* getKey(const QString& database_path); 
};
#endif // KEEPASSX_TOUCHID_H