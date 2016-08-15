//
//  SSLService.swift
//  SSLService
//
//  Created by Bill Abt on 5/26/16.
//
//  Copyright © 2016 IBM. All rights reserved.
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.
//

import Foundation

// MARK: SSLService

///
/// SSL Service Plugin for Socket using OpenSSL
///

public class SSLService : SSLServiceDelegate {
    
    // MARK: Constants
    
    let DEFAULT_VERIFY_DEPTH: Int32				= 2
    
    // MARK: Configuration
    
    ///
    /// SSL Configuration
    ///
    public struct Configuration {
        
        // MARK: Properties
        
        /// File name of CA certificate to be used.
        public private(set) var caCertificateFilePath: String? = nil
        
        /// Path to directory containing hashed CA's to be used.
        ///	*Note:* `caCertificateDirPath` - All certificates in the specified directory **must** be hashed.
        public private(set) var caCertificateDirPath: String? = nil
        
        /// Path to the certificate file to be used.
        public private(set) var certificateFilePath: String? = nil
        
        /// Path to the key file to be used.
        public private(set) var keyFilePath: String? = nil
        
        /// Path to the certificate chain file (optional).
        public private(set) var certificateChainFilePath: String? = nil
        
        /// True if using `self-signed` certificates.
        public private(set) var certsAreSelfSigned = false
        
        /// Cipher suite to use. Defaults to `ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP:+eNULL`
        public var cipherSuite: String
            = "14,13,2B,2F,2C,30,9E,9F,23,27,09,28,13,24,0A,14,67,33,6B,39,08,12,16,9C,9D,3C,3D,2F,35,0A"
        
        
        /// Password ( if needed) typically used for PKCS12 files.
        public var password: String? = nil
        
        // MARK: Lifecycle
        
        ///
        /// Initialize a configuration using a `CA Certificate` file.
        ///
        /// - Parameters:
        ///		- caCertificateFilePath:	Path to the PEM formatted CA certificate file.
        ///		- certificateFilePath:		Path to the PEM formatted certificate file.
        ///		- keyFilePath:				Path to the PEM formatted key file. If nil, `certificateFilePath` will be used.
        ///		- selfSigned:				True if certs are `self-signed`, false otherwise. Defaults to true.
        ///
        ///	- Returns:	New Configuration instance.
        ///
        public init(withCACertificateFilePath caCertificateFilePath: String?, usingCertificateFile certificateFilePath: String?, withKeyFile keyFilePath: String? = nil, usingSelfSignedCerts selfSigned: Bool = true) {
            
            self.certificateFilePath = certificateFilePath
            self.keyFilePath = keyFilePath ?? certificateFilePath
            self.certsAreSelfSigned = selfSigned
            self.caCertificateFilePath = caCertificateFilePath
        }
        
        ///
        /// Initialize a configuration using a `CA Certificate` directory.
        ///
        ///	*Note:* `caCertificateDirPath` - All certificates in the specified directory **must** be hashed using the `OpenSSL Certificate Tool`.
        ///
        /// - Parameters:
        ///		- caCertificateDirPath:		Path to a directory containing CA certificates. *(see note above)*
        ///		- certificateFilePath:		Path to the PEM formatted certificate file. If nil, `certificateFilePath` will be used.
        ///		- keyFilePath:				Path to the PEM formatted key file (optional). If nil, `certificateFilePath` is used.
        ///		- selfSigned:				True if certs are `self-signed`, false otherwise. Defaults to true.
        ///
        ///	- Returns:	New Configuration instance.
        ///
        public init(withCACertificateDirectory caCertificateDirPath: String?, usingCertificateFile certificateFilePath: String?, withKeyFile keyFilePath: String? = nil, usingSelfSignedCerts selfSigned: Bool = true) {
            
            self.certificateFilePath = certificateFilePath
            self.keyFilePath = keyFilePath ?? certificateFilePath
            self.certsAreSelfSigned = selfSigned
            self.caCertificateDirPath = caCertificateDirPath
        }
        
        ///
        /// Initialize a configuration using a `Certificate Chain File`.
        ///
        /// *Note:* If using a certificate chain file, the certificates must be in PEM format and must be sorted starting with the subject's certificate (actual client or server certificate), followed by intermediate CA certificates if applicable, and ending at the highest level (root) CA.
        ///
        /// - Parameters:
        ///		- chainFilePath:			Path to the certificate chain file (optional). *(see note above)*
        ///		- selfSigned:				True if certs are `self-signed`, false otherwise. Defaults to true.
        ///
        ///	- Returns:	New Configuration instance.
        ///
        public init(withChainFilePath chainFilePath: String? = nil, usingSelfSignedCerts selfSigned: Bool = true) {
            
            self.certificateChainFilePath = chainFilePath
            self.certsAreSelfSigned = selfSigned
        }
    }
    
    // MARK: Properties
    
    // MARK: -- Public
    
    /// SSL Configuration (Read only)
    public private(set) var configuration: Configuration
    
    public private(set) var cSSL: SSLContext?
    
    public private(set) var ref: SecIdentity?
    
    public private(set) var instancesock = UnsafeMutablePointer<Int32>.init(allocatingCapacity: 1)
    
    // MARK: -- Private
    
    /// True if setup as server, false if setup as client.
    private var isServer: Bool = true
    
    /// SSL Connection
    //var cSSL: SSLContext?
    
    /// SSL Method
    /// **Note:** We use `SSLv23` which causes negotiation of the highest available SSL/TLS version.
    //private var method: UnsafePointer<SSL_METHOD>? = nil
    
    /// SSL Context
    //private var context: UnsafeMutablePointer<SSL_CTX>? = nil
    
    
    // MARK: Lifecycle
    
    ///
    /// Initialize an SSLService instance.
    ///
    /// - Parameter config:		Configuration to use.
    ///
    /// - Returns: SSLServer instance.
    ///
    public init?(usingConfiguration config: Configuration) throws {
        
        // Store it...
        self.configuration = config
        
        // Validate the config...
        try self.validate(configuration: config)
    }
    
    
    // MARK: SSLServiceDelegate Protocol
    
    ///
    /// Initialize SSL Service
    ///
    /// - Parameter isServer:	True for initializing a server, otherwise a client.
    ///
    public func initialize(isServer: Bool) throws {
        
        // Prepare the context...
        try self.prepareContext()
    }
    
    ///
    /// Deinitialize SSL Service
    ///
    public func deinitialize() {
        //print("deinit \(instancesock.pointee) cSSL=\(self.cSSL)")
        
        // Shutdown and then free SSL pointer...
        if self.cSSL != nil {
            SSLClose(self.cSSL!)
        }

    }
    
    ///
    /// Processing on acceptance from a listening socket
    ///
    /// - Parameter socket:	The connected Socket instance.
    ///
    public func onAccept(socket: Socket) throws {
        
        // Prepare the connection...
        _ = try prepareConnection(socket: socket)

    }
    
    ///
    /// Processing on connection to a listening socket
    ///
    /// - Parameter socket:	The connected Socket instance.
    ///
    public func onConnect(socket: Socket) throws {
        
        // Prepare the connection...
        _ = try prepareConnection(socket: socket)

    }
    
    ///
    /// Do connection verification
    ///
    public func verifyConnection() throws {
        
        // Skip the verification if we're using self-signed certs and we're a server...
        if self.configuration.certsAreSelfSigned && self.isServer {
            return
        }
        
    }
    
    ///
    /// Low level writer
    ///
    /// - Parameters:
    ///		- buffer:		Buffer pointer.
    ///		- bufSize:		Size of the buffer.
    ///
    ///	- Returns the number of bytes written. Zero indicates SSL shutdown, less than zero indicates error.
    ///
    public func send(buffer: UnsafePointer<Void>!, bufSize: Int) throws -> Int {
        
        guard let sslConnect = self.cSSL else {
            
            let reason = "ERROR: SSL_write, code: \(ECONNABORTED), reason: Unable to reference connection)"
            throw SSLError.fail(Int(ECONNABORTED), reason)
        }
        
        var processed = 0
        var status: OSStatus
        repeat {
            status = SSLWrite(sslConnect, buffer, bufSize, &processed)
        } while status == errSSLWouldBlock
        if status != errSecSuccess {
            try self.throwLastError(source: "SSL_write", err: status)
        }
        return processed
    }
    
    ///
    /// Low level reader
    ///
    /// - Parameters:
    ///		- buffer:		Buffer pointer.
    ///		- bufSize:		Size of the buffer.
    ///
    ///	- Returns the number of bytes read. Zero indicates SSL shutdown, less than zero indicates error.
    ///
    public func recv(buffer: UnsafeMutablePointer<Void>!, bufSize: Int) throws -> Int {
        
        guard let sslConnect = self.cSSL else {
            
            let reason = "ERROR: SSL_read, code: \(ECONNABORTED), reason: Unable to reference connection)"
            throw SSLError.fail(Int(ECONNABORTED), reason)
        }
        
        var processed = 0
        var status: OSStatus
        repeat {
            status = SSLRead(sslConnect, buffer, bufSize, &processed)
        } while status == errSSLWouldBlock
        if status != errSecSuccess {
            try self.throwLastError(source: "SSL_read", err: status)
        }
        
        return processed
    }
    
    // MARK: Private Methods
    
    ///
    /// Validate configuration
    ///
    /// - Parameter configuration:	Configuration to validate.
    ///
    private func validate(configuration: Configuration) throws {
        
        // If we're using self-signed certs, we only require a certificate and key...
        if configuration.certsAreSelfSigned {
            
            if configuration.certificateFilePath == nil || configuration.keyFilePath == nil {
                
                throw SSLError.fail(Int(ENOENT), "Certificate and/or key file not specified.")
            }
            
        } else {
            
            // If we don't have a certificate chain file, we require the following...
            if configuration.certificateChainFilePath == nil {
                
                // Need a CA certificate (file or directory)...
                if configuration.caCertificateFilePath == nil && configuration.caCertificateDirPath == nil {
                    
                    throw SSLError.fail(Int(ENOENT), "CA Certificate not specified.")
                }
                
                // Also need a certificate file and key file...
                if configuration.certificateFilePath == nil || configuration.keyFilePath == nil {
                    
                    throw SSLError.fail(Int(ENOENT), "Certificate and/or key file not specified.")
                }
            }
        }
        
        
        // Now check if what's specified actually exists...
        #if os(Linux)
            // See if we've got everything...
            //	- First the CA...
            if let caFile = configuration.caCertificateFilePath {
                
                if !NSFileManager.defaultManager().fileExists(atPath: caFile) {
                    
                    throw SSLError.fail(Int(ENOENT), "CA Certificate doesn't exist in current directory.")
                }
            }
            
            if let caPath = configuration.caCertificateDirPath {
                
                var isDir: ObjCBool = false
                if !NSFileManager.defaultManager().fileExists(atPath: caPath, isDirectory: &isDir) {
                    
                    throw SSLError.fail(Int(ENOENT), "CA Certificate directory path doesn't exist.")
                }
                if !isDir {
                    
                    throw SSLError.fail(Int(ENOENT), "CA Certificate directory path doesn't specify a directory.")
                }
            }
            
            //	- Then the certificate file...
            if let certFilePath = configuration.certificateFilePath {
                
                if !NSFileManager.defaultManager().fileExists(atPath: certFilePath) {
                    
                    throw SSLError.fail(Int(ENOENT), "Certificate doesn't exist at specified path.")
                }
            }
            
            //	- Now the key file...
            if let keyFilePath = configuration.keyFilePath {
                
                if !NSFileManager.defaultManager().fileExists(atPath: keyFilePath) {
                    
                    throw SSLError.fail(Int(ENOENT), "Key file doesn't exist at specified path.")
                }
            }
            
            //	- Finally, if present, the certificate chain path...
            if let chainPath = configuration.certificateChainFilePath {
                
                if !NSFileManager.defaultManager().fileExists(atPath: chainPath) {
                    
                    throw SSLError.fail(Int(ENOENT), "Certificate chain doesn't exist at specified path.")
                }
            }
        #else
            // See if we've got everything...
            //	- First the CA...
            if let caFile = configuration.caCertificateFilePath {
                
                if !FileManager.default().fileExists(atPath: caFile) {
                    
                    throw SSLError.fail(Int(ENOENT), "CA Certificate doesn't exist in current directory.")
                }
            }
            
            if let caPath = configuration.caCertificateDirPath {
                
                var isDir: ObjCBool = false
                if !FileManager.default().fileExists(atPath: caPath, isDirectory: &isDir) {
                    
                    throw SSLError.fail(Int(ENOENT), "CA Certificate directory path doesn't exist.")
                }
                if !isDir {
                    
                    throw SSLError.fail(Int(ENOENT), "CA Certificate directory path doesn't specify a directory.")
                }
            }
            
            //	- Then the certificate file...
            if let certFilePath = configuration.certificateFilePath {
                
                if !FileManager.default().fileExists(atPath: certFilePath) {
                    
                    throw SSLError.fail(Int(ENOENT), "Certificate doesn't exist at specified path.")
                }
            }
            
            //	- Now the key file...
            if let keyFilePath = configuration.keyFilePath {
                
                if !FileManager.default().fileExists(atPath: keyFilePath) {
                    
                    throw SSLError.fail(Int(ENOENT), "Key file doesn't exist at specified path.")
                }
            }
            
            //	- Finally, if present, the certificate chain path...
            if let chainPath = configuration.certificateChainFilePath {
                
                if !FileManager.default().fileExists(atPath: chainPath) {
                    
                    throw SSLError.fail(Int(ENOENT), "Certificate chain doesn't exist at specified path.")
                }
            }
        #endif
    }
    
    ///
    /// Prepare the context.
    ///
    private func prepareContext() throws {

        ///SSL_CTX_set_cipher_list(context, self.configuration.cipherSuite)
        if self.configuration.certsAreSelfSigned {
            ///SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nil)
        } else {
            ///SSL_CTX_set_verify(context, SSL_VERIFY_PEER, nil)
        }
        ///SSL_CTX_set_verify_depth(context, DEFAULT_VERIFY_DEPTH)
        
        // Then handle the client/server specific stuff...
        if !self.isServer {
            
            ///SSL_CTX_ctrl(context, SSL_CTRL_OPTIONS, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION, nil)
        }
        
        // Now configure the rest...
        //	Note: We've already verified the configuration, so we've at least got the minimum requirements.
        // 	- First process the CA certificate(s) if any...
        var rc: Int32 = 0
        if configuration.caCertificateFilePath != nil || configuration.caCertificateDirPath != nil {
            
            let caFile = self.configuration.caCertificateFilePath
            let caPath = self.configuration.caCertificateDirPath
            
            ///rc = SSL_CTX_load_verify_locations(context, caFile, caPath)
            if rc <= 0 {
                
                try self.throwLastError(source: "CA Certificate file/dir", err: rc)
            }
        }
        
        //	- Then the app certificate...
        if let certFilePath = self.configuration.certificateFilePath {
            
            ///rc = SSL_CTX_use_certificate_file(context, certFilePath, SSL_FILETYPE_PEM)
            if rc <= 0 {
                
                try self.throwLastError(source: "Certificate", err: rc)
            }
        }
        
        //	- An' the corresponding Private key file...
        if let keyFilePath = self.configuration.keyFilePath {
            
            ///rc = SSL_CTX_use_PrivateKey_file(context, keyFilePath, SSL_FILETYPE_PEM)
            if rc <= 0 {
                
                try self.throwLastError(source: "Key file", err: rc)
            }
            
            // Check it for consistency...
            ///rc = SSL_CTX_check_private_key(context)
            if rc <= 0 {
                
                try self.throwLastError(source: "Check private key", err: rc)
            }
        }
        
        //	- Finally, if present, the certificate chain path...
        if let chainPath = configuration.certificateChainFilePath {
            
            //rc = SSL_CTX_use_certificate_chain_file(context, chainPath)
            if rc <= 0 {
                
                //try self.throwLastError(source: "Certificate chain file")
            }
        }
    }
    
    ///
    /// Prepare the connection for either server or client use.
    ///
    /// - Parameter socket:	The connected Socket instance.
    ///
    /// - Returns: `UnsafeMutablePointer` to the SSL connection.
    ///
    private func prepareConnection(socket: Socket) throws -> SSLContext {
        
        let sslConfig = SSLService.Configuration(withChainFilePath: self.configuration.certificateChainFilePath, usingSelfSignedCerts: false)
        let service = try SSLService(usingConfiguration: sslConfig)
        
        // Now create the connection...
        let cSSL = SSLCreateContext(kCFAllocatorDefault,SSLProtocolSide.serverSide,SSLConnectionType.streamType)
        service?.cSSL = cSSL!
        socket.delegate = service
        
        
        SSLSetIOFuncs(cSSL!, sslReadCallback, sslWriteCallback)
        
        // load certificates
        guard let certFile = configuration.certificateChainFilePath else {
            let reason = "No PKCS12 file"
            throw SSLError.fail(Int(ENOENT),reason)
        }
        
        var status : OSStatus
        guard let p12Data = NSData(contentsOfFile: certFile) else {
            let reason = "Error reading PKCS12 file"
            throw SSLError.fail(Int(ENOENT),reason)
        }
        
        //create key dictionary for reading p12 file
        guard let passwd : String = self.configuration.password else {
            let reason = "No password for PKCS12 file"
            throw SSLError.fail(Int(ENOENT),reason)
        }
        let key : NSString = kSecImportExportPassphrase as NSString
        let options : NSDictionary = [key : passwd as AnyObject]
        
        var items:CFArray?
        
        status = SecPKCS12Import(p12Data, options, &items)
        if status != errSecSuccess {
            try self.throwLastError(source: "SecPKCS12Import", err: status)
        }
        
        let newArray = items! as [AnyObject] as NSArray
        //let dictionaries = newArray as! [[String:AnyObject]]
        let dictionary = newArray.object(at: 0)
 
        var secIdentityRef = dictionary.value(forKey: kSecImportItemKeyID as String)
        secIdentityRef = dictionary.value(forKey: "identity")
        
        var certs = [secIdentityRef!]
        var ccerts : Array<SecCertificate> = dictionary.value(forKey: kSecImportItemCertChain as String) as! Array<SecCertificate>
        //for certificate in ccerts {
        //    print(certificate)
        //}
        //certs += [ccerts[0] as AnyObject]
        certs += [ccerts[1] as AnyObject]
        certs += [ccerts[2] as AnyObject]
        
        status = SSLSetCertificate(cSSL!, certs as CFArray)
        if status != errSecSuccess {
            try self.throwLastError(source: "SSLSetCertificate", err: status)
        }
        
        
        let cipherlist = configuration.cipherSuite.components(separatedBy: ",")
        //let cipherlist = configuration.cipherSuite.characters.split(separator: ",")
        let eSize = cipherlist.count * sizeof(SSLCipherSuite.self)
        let eCipherSuites : UnsafeMutablePointer<SSLCipherSuite> = UnsafeMutablePointer.init(allocatingCapacity: eSize)
        for i in 0..<cipherlist.count {
            eCipherSuites.advanced(by: i).pointee = UInt32(cipherlist[i] , radix: 16)!
        }
        status = SSLSetEnabledCiphers(cSSL!, eCipherSuites, cipherlist.count)
        if status != errSecSuccess {
            try self.throwLastError(source: "SSLSetConnection", err: status)
        }
        
        /*
        let eSize = 4 * sizeof(SSLCipherSuite.self)
        let eCipherSuites : UnsafeMutablePointer<SSLCipherSuite> = UnsafeMutablePointer.init(allocatingCapacity: eSize)
        eCipherSuites.advanced(by: 0).pointee = UInt32("35" , radix: 16)!
        eCipherSuites.advanced(by: 1).pointee = UInt32("39" , radix: 16)!
        eCipherSuites.advanced(by: 2).pointee = UInt32("67" , radix: 16)!
        eCipherSuites.advanced(by: 3).pointee = UInt32("99" , radix: 16)!
        status = SSLSetEnabledCiphers(cSSL!, eCipherSuites, 4)
        if status != errSecSuccess {
            try self.throwLastError(source: "SSLSetConnection", err: status)
        }
        */
        
        // Set the socket file descriptor...
        //funnysock = socket.socketfd
        service!.instancesock.pointee = socket.socketfd
        //instancesock.pointee = socket.socketfd
        //print("connect \(service!.instancesock.pointee) cSSL=\(service?.cSSL)")
        //let s  = UnsafeMutablePointer<Int32>.init(allocatingCapacity: 1)
        //s.pointee = socket.socketfd
        status = SSLSetConnection(cSSL!, service!.instancesock)
        if status != errSecSuccess {
            try self.throwLastError(source: "SSLSetConnection", err: status)
        }
        
        //print("Handshake on fd=\(socket.socketfd)")
        repeat {
            status = SSLHandshake(cSSL!)
        } while status == errSSLWouldBlock
        if status != errSecSuccess {
            try self.throwLastError(source: "SSLHandshake", err: status)
        }
        
        return cSSL!
    }
    
    private func throwLastError(source: String, err: OSStatus) throws {
        var errorString: String
        if let val = STerrors[err] {
            errorString = val
        } else {
            errorString = "Could not determine error reason."
        }
        let reason = "ERROR: \(source), code: \(err), reason: \(errorString)"
        print("SSLError \(reason)")
        throw SSLError.fail(Int(err), reason)
    }
    
}


private func sslReadCallback(connection: SSLConnectionRef, data: UnsafeMutablePointer<Void>, dataLength: UnsafeMutablePointer<Int>) -> OSStatus {
    
    let socketfd = UnsafePointer<Int32>(connection).pointee
    let bytesRequested = dataLength.pointee
    let bytesRead = read(socketfd, data, UnsafePointer<Int>(dataLength).pointee)
    //print("read \(bytesRead) bytes of \(bytesRequested) from fd=\(socketfd)")
    if (bytesRead > 0) {
        dataLength.initialize(with: bytesRead)
        if bytesRequested > bytesRead {
            return Int32(errSSLWouldBlock)
        } else {
            return noErr
        }
    } else if (bytesRead == 0) {
        dataLength.initialize(with: 0)
        return Int32(errSSLClosedGraceful)
    } else {
        dataLength.initialize(with: 0)
        switch (errno) {
        case ENOENT: return Int32(errSSLClosedGraceful)
        case EAGAIN: return Int32(errSSLWouldBlock)
        case ECONNRESET: return Int32(errSSLClosedAbort)
        default: return Int32(errSecIO)
        }
        
    }
    
}

private func sslWriteCallback(connection: SSLConnectionRef, data: UnsafePointer<Void>, dataLength: UnsafeMutablePointer<Int>) -> OSStatus {
    
    let socketfd = UnsafePointer<Int32>(connection).pointee
    let bytesToWrite = dataLength.pointee
    let bytesWritten = write(socketfd, data, UnsafePointer<Int>(dataLength).pointee)
    //print("wrote \(bytesWritten) of \(bytesToWrite) bytes from fd=\(socketfd)")
    if (bytesWritten > 0) {
        dataLength.initialize(with: bytesWritten)
        if (bytesToWrite > bytesWritten) {
            return Int32(errSSLWouldBlock)
        } else {
            return noErr
        }
    } else if (bytesWritten == 0) {
        dataLength.initialize(with: 0)
        return Int32(errSSLClosedGraceful)
    } else {
        dataLength.initialize(with: 0)
        if (EAGAIN == errno) {
            return Int32(errSSLWouldBlock)
        } else {
            return Int32(errSecIO)
        }
    }
}

let STerrors: [OSStatus: String] = [
    errSecSuccess : "errSecSuccess",
    errSSLNegotiation: "errSSLNegotiation",
    errSecParam: "errSecParam",
    errSSLClosedAbort: "errSSLClosedAbort",
    errSecIO: "errSecIO",
    errSSLWouldBlock: "errSSLWouldBlock",
    errSSLPeerUnknownCA: "errSSLPeerUnknownCA",
    errSSLBadRecordMac: "errSSLBadRecordMac",
    errSecAuthFailed: "errSecAuthFailed"
]
