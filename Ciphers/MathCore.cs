using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace Ciphers
{
    public class MathCore
    {
        //прямое построение
        public static BigInteger FindPrime(int keySize)
        {
            //создаем массив из псевдослучайных байтов
            byte[] randomBytes = new byte[(keySize / 8) + 1];
            //создаем генератор с указанием начального значения( время, истекшее с момента загрузки системы)
            Random rand = new Random(Environment.TickCount);
            //заполняем массив случайными байтами
            rand.NextBytes(randomBytes);
            //чтобы большие чила были без знака
            randomBytes[randomBytes.Length - 1] = 0x0;
            //гарантирует, что число нечетное, и гарантирует, что старший бит N будет установлен при генерации ключей
            SetBitInByte(0, ref randomBytes[0]);
            SetBitInByte(7, ref randomBytes[randomBytes.Length - 2]);
            SetBitInByte(6, ref randomBytes[randomBytes.Length - 2]);

            int numbSearchCycles = 0;
            while (true)
            {
                if (numbSearchCycles == 1000)
                {
                    return new BigInteger(-1);
                }
                numbSearchCycles += 1;
                //с некоторой вероятностью получаем инфу, простое у нас число или нет
                byte[] forTestBytes = randomBytes;
                GenerateSafePrime(ref forTestBytes);
                BigInteger forTest = new BigInteger(forTestBytes);
                bool isPrime = RabinMillerTest(forTest, 40);
                if (isPrime)
                {
                    break;
                }
                else
                //прибавим 1 и проверим на простоту новое число
                {
                    IncrementByteArray(ref randomBytes);
                }
            }
            GenerateSafePrime(ref randomBytes);

            return new BigInteger(randomBytes);
        }

        //тут передается ссылка на изменяемый байт, т.е. локальной копии не создается
        //бит под указанным номером в байте становится равным 1
        public static void SetBitInByte(int bitNumFromRight, ref byte toSet)
        {
            byte mask = (byte)(1 << bitNumFromRight);
            toSet |= mask;
        }

        //true - простое
        //false - составное
        public static bool RabinMillerTest(BigInteger source, int certainty)
        {
            if (source == 2 || source == 3)
            {
                return true;
            }
            if (source < 2 || source % 2 == 0)
            {
                return false;
            }

            BigInteger d = source - 1;
            int s = 0;

            while (d % 2 == 0)
            {
                d /= 2;
                s += 1;
            }

            Random rng = new Random(Environment.TickCount);
            byte[] bytes = new byte[source.ToByteArray().LongLength];
            BigInteger a;

            for (int i = 0; i < certainty; i++)
            {
                do
                {                 
                    rng.NextBytes(bytes);
                    a = new BigInteger(bytes);
                }
                while (a < 2 || a >= source - 2);

                BigInteger x = BigInteger.ModPow(a, d, source);
                if (x == 1 || x == source - 1)
                {
                    continue;
                }

                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, source);
                    if (x == 1)
                    {
                        return false;
                    }
                    else if (x == source - 1)
                    {
                        break;
                    }
                }

                if (x != source - 1)
                {
                    return false;
                }
            }

            return true;
        }
        public static void IncrementByteArray(ref byte[] randomBytes)
        {
            BigInteger n = new BigInteger(randomBytes);
            n += 1;
            randomBytes = n.ToByteArray();
        }

        public static void GenerateSafePrime(ref byte[] randomBytes)
        {
            BigInteger n = new BigInteger(randomBytes);
            n = 2 * n + 1;
            randomBytes = n.ToByteArray();
        }

        public static BigInteger FindPrimitiveRoot(BigInteger primeValue)
        {
            if (primeValue == 2)
            {
                return 1;
            }
            //(primeValue - 1) = p1 * p2 = 2 * ((primeValue - 1) / 2) - факторизация(p1 и p2 - простые числа)
            BigInteger pV = primeValue - 1;
            BigInteger p1 = 2;
            BigInteger p2 = pV / 2;
            byte[] randomBytes = primeValue.ToByteArray();
            //создаем генератор с указанием начального значения( время, истекшее с момента загрузки системы)
            Random rand = new Random(Environment.TickCount);

            BigInteger g;
            while (true)
            {
                //заполняем массив случайными байтами
                rand.NextBytes(randomBytes);
                //чтобы большие чила были без знака
                randomBytes[randomBytes.Length - 1] = 0x0;

                g = new BigInteger(randomBytes);

                //не попали в наш диапазон...попробуем еще 
                if (g < 2 || g > pV)
                {
                    continue;
                }
                //теперь проверим, является сгенерированное g - первообразным корнем
                if (modExp(g, pV / p1, primeValue) != 1)
                {
                    if (modExp(g, pV / p1, primeValue) != 1)
                    {
                        return g;
                    }
                }
                //предотвратить возможность зацикливания и вывести -1 в таком случае
            }
            return -1;
        }

        public static BigInteger modExp(BigInteger baseNum, BigInteger exp, BigInteger modul)
        {
            if (modul == 1)
            {
                return 0;
            }
            BigInteger curPow = baseNum % modul;
            BigInteger res = 1;
            while (exp > 0)
            {
                if ((exp & 1) == 1)
                    res = (res * curPow) % modul;
                exp = exp >> 1;
                curPow = (curPow * curPow) % modul;
            }
            return res;
        }
    }
}
