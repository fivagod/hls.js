import XhrLoader from './xhr-loader';
import { Observer } from '../observer';

import { logger } from '../utils/logger';
import Decrypter from '../crypt/decrypter';

class XhrAesLoader extends XhrLoader {
  constructor (config) {
    super(config);
    if (config && config.aesSetup) {
      this.aesSetup = config.aesSetup;
    }
    this.observer = new Observer();
    this.decrypter = new Decrypter(this.observer, config);
  }
  str2ab (str) {
    let buf = new ArrayBuffer(str.length); // 2 bytes for each char
    let bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  }
  ab2str (buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf));
  }
  load (context, config, callbacks) {
    let needConvertToStr = context.responseType !== 'arraybuffer';
    context.responseType = 'arraybuffer';
    super.load(context, config, callbacks);
    let onSuccess = this.callbacks.onSuccess;
    this.callbacks.onSuccess = (response, stats, context, xhr) => {
      this.decrypter.decrypt(response.data, this.str2ab(this.aesSetup.key), this.str2ab(this.aesSetup.iv), (decryptedData) => {
        response.data = needConvertToStr ? this.ab2str(decryptedData) : decryptedData;
        if (typeof onSuccess === 'function') {
          onSuccess(response, stats, context, xhr);
        }
      });
    };
  }
}

export default XhrAesLoader;
