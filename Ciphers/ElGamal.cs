using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace Ciphers
{
    public class ElGamal
    {
        public BigInteger p;
        public BigInteger g;
        public BigInteger y; //вычисленное открытое число
        private BigInteger x; //секретное число
        public BigInteger friendPublicKey;//публичный ключ чела, с которым я общаюсь
        public BigInteger sessionKey; //сессионный ключ, который я генерирую перед началом шифрования одного байта или
                                      //массива байтов
        public int keySize;
        public ElGamal(int _keySize = 512)
        {
            keySize = _keySize;
            p = MathCore.FindPrime(keySize);
            g = MathCore.FindPrimitiveRoot(p);
            //генерация секретного числа
            byte[] randomBytes = p.ToByteArray();
            Random rand = new Random(Environment.TickCount);
            while (true)
            {
                //заполняем массив случайными байтами
                rand.NextBytes(randomBytes);
                //чтобы большие чиcла были без знака
                randomBytes[randomBytes.Length - 1] = 0x0;
                x = new BigInteger(randomBytes);
                //не попали в наш диапазон...попробуем еще 
                if (x > 1 && x < (p - 1))
                {
                    break;
                }
            }
            //вычисляем открытое число
            y = MathCore.modExp(g, x, p);
        }

        public ElGamal(BigInteger p_, BigInteger g_, int _keySize = 512)
        {
            keySize = _keySize;
            p = p_;
            g = g_;
            //генерация секретного числа
            byte[] randomBytes = p.ToByteArray();
            Random rand = new Random(Environment.TickCount);
            while (true)
            {
                //заполняем массив случайными байтами
                rand.NextBytes(randomBytes);
                //чтобы большие чила были без знака
                randomBytes[randomBytes.Length - 1] = 0x0;

                x = new BigInteger(randomBytes);

                //не попали в наш диапазон...попробуем еще 
                if (x > 1 && x < (p - 1))
                {
                    break;
                }
            }
            //вычисляем открытое число
            y = MathCore.modExp(g, x, p);
        }

        public void SetFriendPublicKey(BigInteger temp)
        {
            friendPublicKey = temp;
        }
        public void GenerateSessionKey()
        {
            byte[] randomBytes = p.ToByteArray();
            Random rand = new Random(Environment.TickCount);
            while (true)
            {
                //заполняем массив случайными байтами
                rand.NextBytes(randomBytes);
                //чтобы большие чила были без знака
                randomBytes[randomBytes.Length - 1] = 0x0;

                sessionKey = new BigInteger(randomBytes);

                //не попали в наш диапазон...попробуем еще 
                if (sessionKey > 1 && sessionKey < (p - 1))
                {
                    break;
                }
            }
        }

        public BigInteger[] EncryptOneByte(BigInteger m, bool generateSessionKey = true)
        {
            if (generateSessionKey)
            {
                GenerateSessionKey();
            }
            BigInteger cipherKey_0;
            BigInteger cipherKey_1;
            BigInteger[] encryptRes = new BigInteger[2];
            cipherKey_0 = MathCore.modExp(g, sessionKey, p);
            cipherKey_1 = BigInteger.Remainder(BigInteger.Multiply(m, MathCore.modExp(friendPublicKey, sessionKey, p)), p);
            encryptRes[0] = cipherKey_0;
            encryptRes[1] = cipherKey_1;
            return encryptRes;
        }

        public BigInteger[] EncryptBytesArray(byte[] inpArr)
        {
            //длина выходного массива len(inpArr) + 1, т.к. первый элемент это первая часть двухкомпонентного шифра для
            //для каждого байта. Она везде одинаковая, так как перед шифрованием сообщения я генерирую сессионный ключ 1 раз 
            //для всего сообщения целиком, а не для каждого байта в отдельности
            GenerateSessionKey();
            BigInteger[] encryptResArr = new BigInteger[inpArr.Length + 1];
            for (int i = 0; i < inpArr.Length; i++)
            {
                if (i == 0)
                {
                    encryptResArr[i] = EncryptOneByte(inpArr[i], false)[0];
                    encryptResArr[i + 1] = EncryptOneByte(inpArr[i], false)[1];
                }
                encryptResArr[i + 1] = EncryptOneByte(inpArr[i], false)[1];
            }
            return encryptResArr;
        }

        public BigInteger Decrypt(BigInteger firstPart, BigInteger secondPart)
        {
            BigInteger r = firstPart;
            BigInteger e = secondPart;
            return BigInteger.Remainder(BigInteger.Multiply(e, MathCore.modExp(r, p - 1 - x, p)), p);
        }
    }
}
