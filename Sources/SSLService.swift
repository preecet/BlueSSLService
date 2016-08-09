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
import Socket
import OpenSSL

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
		public var cipherSuite: String = "ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP:+eNULL"
		
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
	
	// MARK: -- Private
	
	/// True if setup as server, false if setup as client.
	private var isServer: Bool = true
	
	/// SSL Connection
	private var cSSL: UnsafeMutablePointer<SSL>? = nil
	
	/// SSL Method
	/// **Note:** We use `SSLv23` which causes negotiation of the highest available SSL/TLS version.
	private var method: UnsafePointer<SSL_METHOD>? = nil
	
	/// SSL Context
	private var context: UnsafeMutablePointer<SSL_CTX>? = nil
	
	
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
		
		
	}
	
	///
	/// Processing on acceptance from a listening socket
	///
	/// - Parameter socket:	The connected Socket instance.
	///
	public func onAccept(socket: Socket) throws {
		
		let sslConnect = try prepareConnection(socket: socket)
	}
	
	///
	/// Processing on connection to a listening socket
	///
	/// - Parameter socket:	The connected Socket instance.
	///
	public func onConnect(socket: Socket) throws {
		
		let sslConnect = try prepareConnection(socket: socket)
	}
	
	///
	/// Do connection verification
	///
	public func verifyConnection() throws {

		
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
	public func send(buffer: UnsafeRawPointer!, bufSize: Int) throws -> Int {
		
		guard let sslConnect = self.cSSL else {
            
            let reason = "ERROR: SSL_write, code: \(ECONNABORTED), reason: Unable to reference connection)"
            throw SSLError.fail(Int(ECONNABORTED), reason)
        }
        
        var processed = 0
        let rc = SSLWrite(sslConnect, buffer, bufSize, &processed)
        if rc < 0 {
            
            try self.throwLastError(source: "SSL_write")
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
        let rc = SSLRead(sslConnect, buffer, bufSize, &processed)
        if rc < 0 {
            
            try self.throwLastError(source: "SSL_read")
        }
        print(instancesock)
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
		// See if we've got everything...
		//	- First the CA...
		if let caFile = configuration.caCertificateFilePath {
			
			if !FileManager.default.fileExists(atPath: caFile) {
				
				throw SSLError.fail(Int(ENOENT), "CA Certificate doesn't exist in current directory.")
			}
		}
		
		if let caPath = configuration.caCertificateDirPath {
			
			var isDir: ObjCBool = false
			if !FileManager.default.fileExists(atPath: caPath, isDirectory: &isDir) {
				
				throw SSLError.fail(Int(ENOENT), "CA Certificate directory path doesn't exist.")
			}
			#if os(Linux)
				if !isDir {
				
					throw SSLError.fail(Int(ENOENT), "CA Certificate directory path doesn't specify a directory.")
				}
			#else
				if !isDir.boolValue {
					
					throw SSLError.fail(Int(ENOENT), "CA Certificate directory path doesn't specify a directory.")
				}
			#endif
		}
		
		//	- Then the certificate file...
		if let certFilePath = configuration.certificateFilePath {
			
			if !FileManager.default.fileExists(atPath: certFilePath) {
				
				throw SSLError.fail(Int(ENOENT), "Certificate doesn't exist at specified path.")
			}
		}
		
		//	- Now the key file...
		if let keyFilePath = configuration.keyFilePath {
			
			if !FileManager.default.fileExists(atPath: keyFilePath) {
				
				throw SSLError.fail(Int(ENOENT), "Key file doesn't exist at specified path.")
			}
		}
		
		//	- Finally, if present, the certificate chain path...
		if let chainPath = configuration.certificateChainFilePath {
			
			if !FileManager.default.fileExists(atPath: chainPath) {
				
				throw SSLError.fail(Int(ENOENT), "Certificate chain doesn't exist at specified path.")
			}
		}
	}
	
	///
	/// Prepare the context.
	///
	private func prepareContext() throws {
		
		// Make sure we've got the method to use...
		guard let method = self.method else {
			
			let reason = "ERROR: Unable to reference SSL method."
			throw SSLError.fail(Int(ENOMEM), reason)
		}
	}
	
	///
	/// Prepare the connection for either server or client use.
	///
	/// - Parameter socket:	The connected Socket instance.
	///
	/// - Returns: `UnsafeMutablePointer` to the SSL connection.
	///
	private func prepareConnection(socket: Socket) throws -> UnsafeMutablePointer<SSL> {
		
		let sslConfig = SSLService.Configuration(withChainFilePath: self.configuration.certificateChainFilePath, usingSelfSignedCerts: false)
        let service = try SSLService(usingConfiguration: sslConfig)
        
        // Now create the connection...
        let cSSL = SSLCreateContext(kCFAllocatorDefault,SSLProtocolSide.serverSide,SSLConnectionType.streamType)
        service?.cSSL = cSSL!
        socket.delegate = service
        
        SSLSetIOFuncs(cSSL!, sslReadCallback, sslWriteCallback)
        
        // load certificates
        let certFile = configuration.certificateChainFilePath
        var passwd = "test"
        
        var status : OSStatus
        let p12Data : NSData! = NSData(contentsOfFile: certFile!)
        
        //create key dictionary for reading p12 file
        let key : NSString = kSecImportExportPassphrase as NSString
        let options : NSDictionary = [key : passwd as AnyObject]
            
        var items:CFArray?
            
        status = SecPKCS12Import(p12Data, options, &items)

            
        let newArray = items! as [AnyObject] as NSArray
        let dictionary = newArray.object(at: 0)

            
        var secIdentityRef = dictionary.value(forKey: kSecImportItemKeyID as String)
        secIdentityRef = dictionary.value(forKey: "identity")

            
        let certs = [secIdentityRef!] as CFArray

        status = SSLSetCertificate(cSSL!, certs)

        instancesock.pointee = socket.socketfd
        status = SSLSetConnection(cSSL!, instancesock)
        
        status = SSLHandshake(cSSL!)
        
        return cSSL!
		
	}
}

private func sslReadCallback(connection: SSLConnectionRef, data: UnsafeMutablePointer<Void>, dataLength: UnsafeMutablePointer<Int>) -> OSStatus {
    
    let socketfd = UnsafePointer<Int32>(connection).pointee
    let bytesRequested = dataLength.pointee
    let bytesRead = read(socketfd, data, UnsafePointer<Int>(dataLength).pointee)
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
