using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ciphers
{
    public abstract class Feistel
    {
        protected ulong[] RoundKeys;//массив ключей для каждого раунда

        public int FeistelRoundQuantity; //число раундов

        protected int DataSize;
        protected ulong Data;
        protected ulong R;
        protected ulong L;

        private int byteSize = 8;

        public byte[] Encrypt(byte[] dataBytes) //шифрование
        {
            //делим входной блок на 2 элемента - L и R
            ProcessDataBytes(dataBytes);
            //выполняем начальную перестановку(в зависимости от алгоритма шифрования ее может и не быть)
            Hook1();
            
            DoTheJob(true);
            //выполняем конечную перестановку
            Hook2();
            //измененные глобальные переменные L и R превратим в аналог входного формата, т.е. массив байтов размера 8 или 16
            byte[] leftByteArray = new byte[DataSize / 2];
            byte[] rightByteArray = new byte[DataSize / 2];

            if (DataSize == 8)
            {
                leftByteArray = BitConverter.GetBytes((uint)R);
                rightByteArray = BitConverter.GetBytes((uint)L);
            }
            else if (DataSize == 16)
            {
                leftByteArray = BitConverter.GetBytes(R);
                rightByteArray = BitConverter.GetBytes(L);
            }
            else
            {
                throw new ArgumentException("Wrong data block size in the end of the cipher function");
            }

            //теперь мне надо объединить эти массивы в один выходной массив
            byte[] resultByteArray = new byte[DataSize];
            for (int i = 0; i < DataSize / 2; i++)
            {
                resultByteArray[i] = leftByteArray[i];
            }
            for (int i = DataSize / 2; i < DataSize; i++)
            {
                resultByteArray[i] = rightByteArray[i - DataSize / 2];
            }
            return resultByteArray;
        }

        public byte[] Decrypt(byte[] dataBytes) //дешифруем
        {
            ProcessDataBytes(dataBytes);
            Hook1();
            DoTheJob(false);
            Hook2();
            byte[] leftByteArray = new byte[DataSize / 2];
            byte[] rightByteArray = new byte[DataSize / 2];

            if (DataSize == 8)
            {
                leftByteArray = BitConverter.GetBytes((uint)R);
                rightByteArray = BitConverter.GetBytes((uint)L);
            }
            else if (DataSize == 16)
            {
                leftByteArray = BitConverter.GetBytes(R);
                rightByteArray = BitConverter.GetBytes(L);
            }
            else
            {
                throw new ArgumentException("Wrong data block size in the end of the cipher function");
            }

            //теперь мне надо объединить эти массивы в один выходной массив
            byte[] resultByteArray = new byte[DataSize];
            for (int i = 0; i < DataSize / 2; i++)
            {
                resultByteArray[i] = leftByteArray[i];
            }
            for (int i = DataSize / 2; i < DataSize; i++)
            {
                resultByteArray[i] = rightByteArray[i - DataSize / 2];
            }
            return resultByteArray;
        }

        protected void ProcessDataBytes(byte[] DataBytes) //?????
        {
            DataSize = DataBytes.Length;

            if (DataBytes.Length == 8)
            {
                R = BitConverter.ToUInt32(DataBytes, 0);
                L = BitConverter.ToUInt32(DataBytes, DataSize / 2);
                //теперь в глобальной переменной R лежит 32 бита и в глобальной переменной L лежит 32 бита
            }
            else if (DataSize == 16)
            {
                R = BitConverter.ToUInt64(DataBytes, 0);
                L = BitConverter.ToUInt64(DataBytes, DataSize / 2);
            }
            else
            {
                throw new ArgumentException("Wrong data block size");
            }
        }

        //в этой штуке локализован проход по всем раундам и соответствующие вычисления, замены и перестановки
        protected void DoTheJob(bool encrypt)
        {
            ulong PreviousL = L;
            ulong PreviousR = R;

            for (byte Round = 0; Round < FeistelRoundQuantity; Round++)
            {
                if (encrypt)
                {
                    L = PreviousR;
                    R = PreviousL ^ AbstractFeistelFunction(PreviousR, RoundKeys[Round]);
                    PreviousL = L;
                    PreviousR = R;
                }
                else
                {
                    R = PreviousL;
                    L = PreviousR ^ AbstractFeistelFunction(PreviousL, RoundKeys[FeistelRoundQuantity - 1 - Round]);
                    PreviousR = R;
                    PreviousL = L;
                }
            }
        }
        protected abstract ulong AbstractFeistelFunction(ulong R, ulong RoundKey);//функция фейстеля для шифрования
        //InitialPermutation
        protected virtual void Hook1() { } //начальная перестановка
        //FinalPermutation
        protected virtual void Hook2() { }

        //описание свойства для задания массива раундовых ключей
        public abstract byte[] Key
        {
            set;
        }
    }
}
