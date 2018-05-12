#ifndef BUFFER_H
#define BUFFER_H

//Idea from: Nigshoxiz / DemoHn -> github.com/DemoHn
//Found here: https://github.com/DemoHn/asyncDNS-Qt/blob/master/buffer.cpp
//Rewritten to be safer and consitently compiled across platforms to still work properly across platforms
//Thanks for showing me a better way to do what I was doing though Nigshoxiz! :)

//Note from during rewriting: Scratch that, it's also unsafe, as different compilers compile it differently making it crash on some platforms
//so I'm re-writing it as a c++ templated parameter pack function instead of old c style var_arg (which is causing undefined behavior and incompatibility)

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
    void* var;
    quint64 size;
};

//And let's make it inlined, because why not? :)
//+ Make it composed of a QByteArray instead of inheriting from it (I don't see the need to)

class ModernBuffer
{
public:
    ModernBuffer(const ModernBuffer &buffer)
    {
        buf = buffer.buf;
        fmtLen = fmtIndex = 0;
    }
    ModernBuffer(QByteArray &buffer)
    {
        buf = buffer;
        fmtLen = fmtIndex = 0;
    }
    ModernBuffer(const char *buffer, quint64 length)
    {
        buf.append(buffer, length);
        fmtLen = fmtIndex = 0;
    }
    ModernBuffer(quint64 startingSize)
    {
        buf.resize(startingSize);
        fmtLen = fmtIndex = 0;
    }
    ModernBuffer() { fmtLen = fmtIndex = 0; }

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

    /*
     * B : Byte : 1 byte (unsigned char)
     * W : Word : 2 bytes (unsigned short)
     * L : Long : 4 bytes (unsigned int)
     * I : LongLong : 8 bytes (unsigned long long)
     * Z : String : N bytes (char* that ends with '\0')
     * x : QByteArray : N bytes (QByteArray doesn't need to be null terminated)
     */

    template<class T, class... Params> static QByteArray pack(const char *fmt, T source, Params... next)
    {
        ModernBuffer buffer;
        buffer.pack(fmt, source, next...);
        return buffer.buf;
    }

    template<class T, class... Params> quint64 pack(const char *fmt, T source, Params... next)
    {
        this->fmt = fmt;
        fmtLen = strlen(fmt);
        fmtIndex = 0;
        packedLen = 0;

        return pack(source, next...);
    }

    template<class T, class... Params> quint64 pack(T source, Params... next)
    {
        doPackStep(source);

        return unpack(next...);
    }

    template<class T> quint64 pack(T source)
    {
        doPackStep(source);

        return packedLen;
    }

    template<class T> void doPackStep(T source)
    {
        if((fmtIndex) == fmtLen || fmt[fmtIndex] == 0)
            return;

        if(fmt[fmtIndex] == 'B')
        {
            quint8 byte = *(quint8*)source;
            buf.append(byte);
            packedLen++;
        }
        else if(fmt[fmtIndex] == 'W')
        {
            quint16 word = *(quint16*)source;
            buf.append(word);
            packedLen += 2;
        }
        else if(fmt[fmtIndex] == 'L')
        {
            quint32 Long = *(quint32*)source;
            buf.append(Long);
            packedLen += 4;
        }
        else if(fmt[fmtIndex] == 'I')
        {
            quint64 LongLong = *(quint64*)source;
            buf.append(LongLong);
            packedLen += 8;
        }
        else if(fmt[fmtIndex] == 'Z')
        {
            size_t len = strlen((const char*)source);
            buf.append(source, len);
        }
        else if(fmt[fmtIndex] == 'x')
        {
            buf.append(source);
        }
    }

    /*
    unpack:
    B : Byte : 1 byte
    W : Word : 2 bytes
    L : Long : 4 bytes
    I : LongLong : 8 bytes
    [<num>] : <num> bytes. e.g. : [5] represents for 5 bytes (for an arbitrary known length to copy)
    [&<num>] : its length is determined by the value of the <num>th variable.
    e.g. : "BBBL[&3]" <--> "BBBL[7]" if the parsing data is (00 01 07 04 03 02 01 [01 02 03 04 05 06 07])
    NOTICE : the referenced data is restricted before it. And QByteArray type is not counted.
    e.g. :
    "BB[32]L[&3]" --> refers to the value of "L" format data. the "[32]" is not counted when calculating the order.
    */

    template<class T, class... Params> static quint64 unpack(QByteArray &buff, const char *fmt, T destination, Params... next)
    {
        ModernBuffer buffer(buff);
        return buffer.unpack(fmt, destination, next...);
    }

    template<class T, class... Params> quint64 unpack(const char *fmt, T destination, Params... next)
    {
        this->fmt = fmt;
        fmtLen = strlen(fmt);
        fmtIndex = 0;
        unpackedLen = 0;
        vars.clear();

        return unpack(destination, next...);
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
        if((fmtIndex) == fmtLen || fmt[fmtIndex] == 0)
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
            *(quint16*)destination = *(quint16*)buf.data();
            buf.remove(0, 2);
            vars.push_back(Var(destination, 2));
            unpackedLen += 2;
        }
        else if(fmt[fmtIndex] == 'L')
        {
            if(buf.size() < 4) return;
            *(quint32*)destination = *(quint32*)buf.data();
            buf.remove(0, 4);
            vars.push_back(Var(destination, 4));
            unpackedLen += 4;
        }
        else if(fmt[fmtIndex] == 'I')
        {
            if(buf.size() < 8) return;
            *(quint64*)destination = *(quint64*)buf.data();
            buf.remove(0, 8);
            vars.push_back(Var(destination, 8));
            unpackedLen += 8;
        }
        else if(fmt[fmtIndex] == '[')
        {
            fmtIndex++;
            if(fmt[fmtIndex] == '&') //referencing a variable to use as the size of this variable
            {
                fmtIndex++;
                quint64 referencingVarNum = extractUpToNextClosingBracket();

                if(referencingVarNum == 0 || referencingVarNum > vars.size())
                {
                    qDebug() << "Check your format string, you're trying to crash me and I'm not having it!";
                    qDebug() << "Either we reached the end before encountering a closing bracket, or the referencing variable doesn't exist";
                    return;
                }

                quint64 varLen = vars[referencingVarNum - 1].size;
                memcpy(&varLen, vars[referencingVarNum - 1].var, varLen);

                if((quint64)buf.size() < varLen) return;
                if(type_name<decltype(destination)>() == type_name<decltype(&buf)>())
                {
                    //Copy to a QByteArray
                    QByteArray *dest = (QByteArray*)destination;
                    dest->resize(varLen);
                    memcpy(dest->data(), buf.data(), varLen);
                }
                else //Or copy to any allocated memory (there better be enough there if you call it like this)
                    memcpy(destination, buf.data(), varLen);

                buf.remove(0, varLen);
                unpackedLen += varLen;
            }
            else //just using the size provided as the size of this variable
            {
                quint64 varLen = extractUpToNextClosingBracket();

                if(varLen == 0 || varLen > (quint64)buf.size())
                {
                    qDebug() << "Check your format string, you're trying to crash me and I'm not having it!";
                    qDebug() << "Either we reached the end before encountering a closing bracket, or specified variable length exceeds remaining buffer to extract it from";
                }

                if(type_name<decltype(destination)>() == type_name<decltype(&buf)>())
                {
                    //Copy to a QByteArray
                    QByteArray *dest = (QByteArray*)destination;
                    dest->resize(varLen);
                    memcpy(dest->data(), buf.data(), varLen);
                }
                else //Or copy to any allocated memory (there better be enough there if you call it like this)
                    memcpy(destination, buf.data(), varLen);

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
};

#endif // BUFFER_H
