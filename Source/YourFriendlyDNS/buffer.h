#ifndef BUFFER_H
#define BUFFER_H

//Idea from: Nigshoxiz / DemoHn -> github.com/DemoHn
//Found here: https://github.com/DemoHn/asyncDNS-Qt/blob/master/buffer.cpp
//Rewritten to be safer and consistently compiled across platforms to still work properly across platforms
//Thanks for showing me a better way to do what I needed to do Nigshoxiz! :)
//Rewritten by softwareengineer1 @ github.com/softwareengineer1
//Part of YourFriendlyDNS, found at github.com/softwareengineer1/YourFriendlyDNS

//Note from during rewriting: Scratch that, it's also unsafe, as different compilers compile it differently making it crash on some platforms
//so I'm re-writing it as a c++ templated parameter pack function instead of old c style var_arg (which is causing undefined behavior and incompatibility)

/* This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA. */

#include <QtEndian>
#include <QByteArray>
#include <QString>
#include <QDebug>
#include <type_traits>
#include <typeinfo>

template <class T> std::string type_name()
{
    typedef typename std::remove_reference<T>::type TR;
    std::string r = typeid(TR).name();
    if (std::is_const<TR>::value)
        r += " const";
    if (std::is_volatile<TR>::value)
        r += " volatile";
    if (std::is_lvalue_reference<T>::value)
        r += "&";
    else if (std::is_rvalue_reference<T>::value)
        r += "&&";
    return r;
}

class Var
{
public:
    Var(void *pVar, quint64 varSize)
    {
        var = pVar;
        size = varSize;
    }
    void *var;
    quint64 size;
};

//When PACKED_BUFFER_IS_BIG_ENDIAN flag is set and when your host byte order is little endian (ex. x86_64),
//it will pack from little endian source variables into a big endian buffer, and unpack from a big endian buffer to little endian destination variables.
//if your host byte order is big endian no change will occur when packing or unpacking as the bytes will already be in the right order.
//When PACKED_BUFFER_IS_BIG_ENDIAN flag is not set and when your host byte order is big endian (ex. PowerPC),
//it will pack from big endian source variables into a little endian buffer, and unpack from a little endian buffer to big endian destination variables
//if your host byte order is little endian then no change will occur when packing or unpacking as the bytes will already be in the right order.

#define PACKED_BUFFER_IS_BIG_ENDIAN 1

class ModernBuffer
{
public:
    ModernBuffer(const ModernBuffer &buffer)
    {
        buf = buffer.buf;
        init();
    }
    ModernBuffer(const QByteArray &buffer)
    {
        buf = buffer;
        init();
    }
    ModernBuffer(const char *buffer, quint64 length)
    {
        buf.append(buffer, length);
        init();
    }
    ModernBuffer(quint64 startingSize)
    {
        buf.reserve(startingSize);
        init();
    }
    ModernBuffer() { init(); }
    void init(bool isBigEndian = true)
    {
        flags = fmtIndex = fmtLen = packedLen = unpackedLen = 0;
        if(isBigEndian)
            flags |= PACKED_BUFFER_IS_BIG_ENDIAN;
    }


     /* pack:
     * B : Byte : 1 byte (unsigned char)
     * W : Word : 2 bytes (unsigned short)
     * L : Long : 4 bytes (unsigned int)
     * I : LongLong : 8 bytes (unsigned long long)
     * T : typename T : Experimental any type (this is the only time you pass a full type directly rather than by reference/pointer)
     * Z : String : N bytes (char* that ends with '\0')
     * z : Prefixed Length String : [N][N Bytes] (char* that's prefixed with it's length using a single byte) from a QString or QByteArray
     * x : QByteArray or QString : N bytes (doesn't need to be null terminated and it uses it's size for N bytes)
     */

    template<class... Params> static quint64 pack(QByteArray &buff, const char *fmt, Params... parameters)
    {
        ModernBuffer buffer;
        buffer.pack(fmt, parameters...);
        buff = buffer.buf;
        return buffer.packedLen;
    }

    template<class... Params> quint64 pack(const char *fmt, Params... parameters)
    {
        this->fmt = fmt;
        fmtLen = strlen(fmt);
        fmtIndex = 0;
        packedLen = 0;

        return pack(parameters...);
    }

    template<class T, class... Params> quint64 pack(T source, Params... next)
    {
        doPackStep(source);

        return pack(next...);
    }

    template<class T> quint64 pack(T source)
    {
        doPackStep(source);

        return packedLen;
    }

    template<class T> void doPackStep(T source)
    {
        if(fmtIndex == fmtLen || fmt[fmtIndex] == 0)
            return;

        if(fmt[fmtIndex] == 'B')
        {
            quint8 byte = *(quint8*)source;
            buf.append(byte);
            packedLen++;
        }
        else if(fmt[fmtIndex] == 'W')
        {
            quint16 word;
            if(flags & PACKED_BUFFER_IS_BIG_ENDIAN)
                word = qToBigEndian(*(quint16*)source);
            else
                word = qToLittleEndian(*(quint16*)source);
            buf.append((const char*)&word, 2);
            packedLen += 2;
        }
        else if(fmt[fmtIndex] == 'L')
        {
            quint32 Long;
            if(flags & PACKED_BUFFER_IS_BIG_ENDIAN)
                Long = qToBigEndian(*(quint32*)source);
            else
                Long = qToLittleEndian(*(quint32*)source);
            buf.append((const char*)&Long, 4);
            packedLen += 4;
        }
        else if(fmt[fmtIndex] == 'I')
        {
            quint64 LongLong;
            if(flags & PACKED_BUFFER_IS_BIG_ENDIAN)
                LongLong = qToBigEndian(*(quint64*)source);
            else
                LongLong = qToLittleEndian(*(quint64*)source);
            buf.append((const char*)&LongLong, 8);
            packedLen += 8;
        }
        /*else if(fmt[fmtIndex] == 'T') //Any type
        {
            T typeT;
            qDebug() << "Packing typeT:" << type_name<decltype(typeT)>().c_str() << "size:" << sizeof typeT;

            if(flags & PACKED_BUFFER_IS_BIG_ENDIAN)
                typeT = qToBigEndian(*(T*)source);
            else
                typeT = qToLittleEndian(*(T*)source);

            buf.append((const char*)&typeT, sizeof typeT);
            packedLen += sizeof typeT;
        }*/
        else if(fmt[fmtIndex] == 'Z') //Null-terminated C String
        {
            size_t len = strlen((const char*)source);
            buf.append((const char*)source, len + 1);
            packedLen += len + 1;
        }
        else if(fmt[fmtIndex] == 'z') //Prefixed Length String
        {
            quint8 prefixedLen;
            QString *s;
            if(type_name<decltype(source)>() == type_name<decltype(&buf)>())
            {
                QByteArray *src = (QByteArray*)source;
                prefixedLen = src->size();
                buf.append(prefixedLen);
                buf.append(*src);
                packedLen += prefixedLen + 1;
            }
            else if(type_name<decltype(source)>() == type_name<decltype(s)>())
            {
                s = (QString*)source;
                prefixedLen = s->size();
                buf.append(prefixedLen);
                buf.append(*s);
                packedLen += prefixedLen + 1;
            }
        }
        else if(fmt[fmtIndex] == 'x') //QByteArray or QString
        {
            QString *s;
            if(type_name<decltype(source)>() == type_name<decltype(&buf)>())
            {
                QByteArray *src = (QByteArray*)source;
                buf.append(*src);
                packedLen += src->size();
            }
            else if(type_name<decltype(source)>() == type_name<decltype(s)>())
            {
                s = (QString*)source;
                buf.append(*s);
                packedLen += s->size();
            }
        }

        fmtIndex++;
    }

    /* unpack:
    B : Byte : 1 byte
    W : Word : 2 bytes
    L : Long : 4 bytes
    I : LongLong : 8 bytes
    Z : String : N bytes (char* that ends with '\0') *this and below (can unpack into QString, QByteArray, or raw array)
    z : Prefixed Length String : [N][N bytes] (char* that's prefixed with it's length using a single byte)
    [<num>] : <num> bytes. e.g. : [5] represents 5 bytes (for an arbitrary known length to copy)
    [&<num>] : its length is determined by the value of the <num>th variable.
    e.g. : "BBBL[&3]" <--> "BBBL[7]" if the parsing data is (00 01 07 04 03 02 01 [01 02 03 04 05 06 07])
    NOTICE : the referenced data is restricted before it. And QByteArray type is not counted.
    e.g. :
    "BB[32]L[&3]" --> refers to the value of "L" format data. the "[32]" is not counted when calculating the order.
    */

    template<class... Params> static quint64 unpack(QByteArray &buff, const char *fmt, Params... parameters)
    {
        ModernBuffer buffer(buff);
        return buffer.unpack(fmt, parameters...);
    }

    template<class... Params> quint64 unpack(const char *fmt, Params... parameters)
    {
        this->fmt = fmt;
        fmtLen = strlen(fmt);
        fmtIndex = 0;
        unpackedLen = 0;
        vars.clear();

        return unpack(parameters...);
    }

    template<class T, class... Params> quint64 unpack(T destination, Params... next)
    {
        doUnpackStep(destination);

        return unpack(next...);
    }

    template<class T> quint64 unpack(T destination)
    {
        doUnpackStep(destination);

        return unpackedLen;
    }

    template<class T> void doUnpackStep(T destination)
    {
        if(fmtIndex == fmtLen || fmt[fmtIndex] == 0)
            return;

        if(fmt[fmtIndex] == 'B')
        {
            if(buf.size() < 1) return;
            *(quint8*)destination = buf.at(0);
            buf.remove(0, 1);
            vars.push_back(Var(destination, 1));
            unpackedLen++;
        }
        else if(fmt[fmtIndex] == 'W')
        {
            if(buf.size() < 2) return;
            if(flags & PACKED_BUFFER_IS_BIG_ENDIAN)
                *(quint16*)destination = qFromBigEndian(*(quint16*)buf.data());
            else
                *(quint16*)destination = qFromLittleEndian(*(quint16*)buf.data());
            buf.remove(0, 2);
            vars.push_back(Var(destination, 2));
            unpackedLen += 2;
        }
        else if(fmt[fmtIndex] == 'L')
        {
            if(buf.size() < 4) return;
            if(flags & PACKED_BUFFER_IS_BIG_ENDIAN)
                *(quint32*)destination = qFromBigEndian(*(quint32*)buf.data());
            else
                *(quint32*)destination = qFromLittleEndian(*(quint32*)buf.data());
            buf.remove(0, 4);
            vars.push_back(Var(destination, 4));
            unpackedLen += 4;
        }
        else if(fmt[fmtIndex] == 'I')
        {
            if(buf.size() < 8) return;
            if(flags & PACKED_BUFFER_IS_BIG_ENDIAN)
                *(quint64*)destination = qFromBigEndian(*(quint64*)buf.data());
            else
                *(quint64*)destination = qFromLittleEndian(*(quint64*)buf.data());
            buf.remove(0, 8);
            vars.push_back(Var(destination, 8));
            unpackedLen += 8;
        }
        else if(fmt[fmtIndex] == 'Z') //C String
        {
            int strLen = -1;
            for(int i = 0; i < buf.size(); i++)
            {
                if(buf.at(i) == '\0')
                {
                    strLen = i;
                    break;
                }
            }
            if(strLen == -1) return;

            copyBytesToDestination(destination, strLen);

            buf.remove(0, strLen + 1);
            unpackedLen += strLen + 1;
        }
        else if(fmt[fmtIndex] == 'z') //Prefixed Length String
        {
            if(buf.size() < 1) return;
            quint8 prefixedLen = buf.at(0);
            buf.remove(0, 1);
            if(buf.size() < prefixedLen) return;

            copyBytesToDestination(destination, prefixedLen);

            buf.remove(0, prefixedLen);
            unpackedLen += prefixedLen;
        }
        else if(fmt[fmtIndex] == '[')
        {
            fmtIndex++;
            if(fmtIndex == fmtLen || fmt[fmtIndex] == 0) return;
            if(fmt[fmtIndex] == '&') //referencing a variable to use as the size of this variable
            {
                fmtIndex++;
                quint64 referencingVarNum = extractUpToNextClosingBracket();

                if(referencingVarNum == 0 || referencingVarNum > vars.size())
                {
                    qDebug() << "Check your format string, you're doing it wrong!";
                    qDebug() << "Either we reached the end before encountering a closing bracket, or the referencing variable doesn't exist";
                    return;
                }

                quint64 refVarLen = vars[referencingVarNum - 1].size, varLen = 0;
                if(refVarLen <= sizeof varLen)
                    memcpy(&varLen, vars[referencingVarNum - 1].var, refVarLen);

                if((quint64)buf.size() < varLen) return;

                copyBytesToDestination(destination, varLen);

                buf.remove(0, varLen);
                unpackedLen += varLen;
            }
            else //just using the size provided as the size of this variable
            {
                quint64 varLen = extractUpToNextClosingBracket();

                if(varLen == 0 || varLen > (quint64)buf.size())
                {
                    qDebug() << "Check your format string, you're doing it wrong! ;)";
                    qDebug() << "Either we reached the end before encountering a closing bracket, or specified variable length exceeds remaining buffer to extract it from";
                    return;
                }

                copyBytesToDestination(destination, varLen);

                buf.remove(0, varLen);
                unpackedLen += varLen;
            }
        }

        fmtIndex++;
    }

    const char *fmt;
    QByteArray buf;
    std::vector<Var> vars;
    quint64 fmtIndex, fmtLen, unpackedLen, packedLen;
    quint8 flags;

private:
    template<class T> void copyBytesToDestination(T destination, size_t numBytes)
    {
        QString str;
        if(type_name<decltype(destination)>() == type_name<decltype(&buf)>())
        {
            //Copy to a QByteArray
            QByteArray *dest = (QByteArray*)destination;
            dest->resize(numBytes);
            memcpy(dest->data(), buf.data(), numBytes);
        }
        else if(type_name<decltype(destination)>() == type_name<decltype(&str)>())
        {
            //Or copy to a QString
            QString *qstr = (QString*)destination;
            QByteArray dest;
            dest.resize(numBytes);
            memcpy(dest.data(), buf.data(), numBytes);
            *qstr = dest;
        }
        else //Or copy to any allocated memory (there better be enough there if you call it like this)
            memcpy((void*)destination, buf.data(), numBytes);
    }
    quint64 extractUpToNextClosingBracket()
    {
        QString extractedNum;
        while(fmtIndex < fmtLen)
        {
            extractedNum += fmt[fmtIndex++];
            if(fmt[fmtIndex] == ']')
            {
                return extractedNum.toLongLong();
            }
        }
        return 0;
    }
};

#endif // BUFFER_H
