import { utf8Encode } from '@angular/compiler/src/util';
import { Component } from '@angular/core';
import * as CryptoJS from 'crypto-js';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent {
  title = 'aes-bytes';

  constructor() {
    const encoder = new TextEncoder();
    const bytes = encoder.encode('Hare Krishna');
    // console.log('bytes', bytes);
    const key = 'YmNjYzc5NDAtZjZhMC0xMWVjLTkyOGEt';
    const encryptedBytes = this.encryptBytes(key, bytes);
    console.log('Encrypted Data: ', encryptedBytes);

    // tslint:disable-next-line:max-line-length
    const encBytes = new Uint8Array([83, 97, 108, 116, 101, 100, 95, 95, 83, 97, 108, 116, 101, 100, 95, 95, 124, 34, 16, 132, 157, 108, 218, 86, 31, 232, 209, 213, 165, 79, 112, 20]);
    const decryptedBytes = this.decryptBytes(key, encBytes);
    console.log('Decrypted: ', new TextDecoder().decode(decryptedBytes));
    // this.decryptBytesString();
  }

  encryptBytes(key: string, bytes: Uint8Array): Uint8Array {
    const encoder = new TextEncoder();
    const magic = encoder.encode('Salted__');
    const pass = encoder.encode(key);
    // console.log('pass', pass);
    // const salt = CryptoJS.lib.WordArray.random(8);
    const salt = encoder.encode('Salted__');
    // console.log('salt', salt);
    const passAndSalt = this._concatUint8Array(pass, salt);
    // console.log('passAndSalt', passAndSalt);

    let keyAndIv = new Uint8Array(0);
    let hash = new Uint8Array(0);
    for (let i = 0; i < 3 && keyAndIv.length < 48; i++) {
      const hashData = this._concatUint8Array(hash, passAndSalt);
      // console.log('Hash Data', hashData);
      // console.log('Hash str', new TextDecoder().decode(hashData));

      const shahash = CryptoJS.MD5(new TextDecoder().decode(hashData));
      const shahashStr = shahash.toString();
      hash = new TextEncoder().encode(shahashStr);
      // console.log('Sha hash md5', hash);
      // console.log('hash md5', shahashStr);

      keyAndIv = this._concatUint8Array(keyAndIv, hash);
    }

    // console.log('KeyAndIV', keyAndIv);

    const keyVal = keyAndIv.slice(0, 32);
    const iv = keyAndIv.slice(32, 48);

    // console.log('Keyvalue', keyVal);
    // console.log('iv', iv);

    const wordArrayData = CryptoJS.lib.WordArray.create(bytes as any as number[]);
    const passWordArray = this._convertUint8ArrayToWordArray(keyVal);
    const encrypted = CryptoJS.AES.encrypt(wordArrayData, passWordArray, {
      padding: CryptoJS.pad.Pkcs7,
      mode: CryptoJS.mode.CBC,
      iv: this._convertUint8ArrayToWordArray(iv)
    });

    const encDataPrefix = this._concatUint8Array(magic, salt);
    const encDataSuffix = this._convertWordArrayToUint8Array(encrypted.ciphertext);
    const encBytes = this._concatUint8Array(encDataPrefix, encDataSuffix);

    // console.log('Bytes Data', encBytes);

    return encBytes;
  }

  // $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

  decryptBytes(key: string, inBytes: Uint8Array): Uint8Array {
    const encoder = new TextEncoder();
    const magic = encoder.encode('Salted__');
    const pass = encoder.encode(key);
    const salt = inBytes.slice(magic.length, magic.length + 8);
    const passAndSalt = this._concatUint8Array(pass, salt);

    let keyAndIv = new Uint8Array(0);
    let hash = new Uint8Array(0);
    for (let i = 0; i < 3 && keyAndIv.length < 48; i++) {
      const hashData = this._concatUint8Array(hash, passAndSalt);
      // console.log('Hash Data', hashData);
      // console.log('Hash str', new TextDecoder().decode(hashData));

      const shahash = CryptoJS.MD5(new TextDecoder().decode(hashData));
      const shahashStr = shahash.toString();
      hash = new TextEncoder().encode(shahashStr);
      // console.log('Sha hash md5', hash);
      // console.log('hash md5', shahashStr);
      keyAndIv = this._concatUint8Array(keyAndIv, hash);
    }

    // console.log('KeyAndIV', keyAndIv);

    const keyVal = keyAndIv.slice(0, 32);
    const iv = keyAndIv.slice(32, 48);

    const encBytes = inBytes.slice(16);

    const passWordArray = this._convertUint8ArrayToWordArray(keyVal);
    const wordArrayData = CryptoJS.lib.WordArray.create(encBytes as any as number[]);
    const cipherParamsData = CryptoJS.lib.CipherParams.create({
      key: passWordArray,
      ciphertext: wordArrayData,
      padding: CryptoJS.pad.Pkcs7,
      iv: this._convertUint8ArrayToWordArray(iv)
    });

    const decrypted = CryptoJS.AES.decrypt(cipherParamsData, passWordArray, {
      padding: CryptoJS.pad.Pkcs7,
      mode: CryptoJS.mode.CBC,
      iv: this._convertUint8ArrayToWordArray(iv)
    });

    return this._convertWordArrayToUint8Array(decrypted);
  }

  // ##############################################################################################

  fileChanged(e: any): void {
    const file = e?.target?.files?.length && e.target.files[0];
    this.readDocument(file);
  }

  readDocument(file: File): void {
    const fileReader = new FileReader();
    fileReader.onload = (_) => {
      const bytes = fileReader?.result;
      console.log(bytes);
      const array = new Uint8Array(fileReader?.result as ArrayBufferLike);
      console.log(array);
    };
    fileReader.readAsArrayBuffer(file);
  }

  _strToBytes(str: string): Uint8Array {
    const utf8Encoder = new TextEncoder();
    return utf8Encoder.encode(str);
  }

  _concatUint8Array(a: Uint8Array, b: Uint8Array): Uint8Array {
    const data = new Uint8Array(a.length + b.length);
    data.set(a);
    data.set(b, a.length);
    return data;
  }

  _convertUint8ArrayToWordArray(u8Array: Uint8Array): any {
    const words = []; let i = 0; const len = u8Array.length;

    while (i < len) {
      words.push(
        // tslint:disable-next-line:no-bitwise
        (u8Array[i++] << 24) |
        // tslint:disable-next-line:no-bitwise
        (u8Array[i++] << 16) |
        // tslint:disable-next-line:no-bitwise
        (u8Array[i++] << 8) |
        (u8Array[i++])
      );
    }

    return {
      sigBytes: words.length * 4,
      words
    };
  }

  _convertWordArrayToUint8Array(decrypted: any): Uint8Array {
    const dataArray = new Uint8Array(decrypted.sigBytes);
    for (let i = 0x0; i < decrypted.sigBytes; i++) {
      // tslint:disable-next-line:no-bitwise
      dataArray[i] = decrypted.words[i >>> 0x2] >>> 0x18 - i % 0x4 * 0x8 & 0xff;
    }
    const data = new Uint8Array(dataArray);
    return data;
  }

}
