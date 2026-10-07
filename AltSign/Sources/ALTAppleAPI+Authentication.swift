//
//  ALTAppleAPI+Authentication.swift
//  AltSign
//
//  Created by Riley Testut on 8/15/20.
//  Copyright © 2020 Riley Testut. All rights reserved.
//

import Foundation

@_exported import CAltSign
import CAltSign.Private

public extension ALTAppleAPIError
{
    static func unknown(statusCode: Int? = nil, failure: String? = nil, userInfo: [String: Any] = [:], sourceFile: String = #fileID, sourceLine: UInt = #line) -> ALTAppleAPIError
    {
        var userInfo = userInfo
        userInfo[ALTSourceFileErrorKey] = sourceFile
        userInfo[ALTSourceLineErrorKey] = sourceLine
        
        if let failure
        {
            userInfo[NSLocalizedFailureErrorKey] = failure
        }
        
        if let statusCode
        {
            userInfo[ALTHTTPStatusCode] = statusCode
            userInfo[NSLocalizedFailureReasonErrorKey] = String(format: NSLocalizedString("Apple's authentication servers returned an error (HTTP %d).", comment: ""), statusCode)
            
            if statusCode >= 300
            {
                userInfo[NSLocalizedRecoverySuggestionErrorKey] = NSLocalizedString("This is most likely a problem on Apple's end, not with your Apple ID or password.", comment: "")
            }
        }
        
        let error = ALTAppleAPIError(.unknown, userInfo: userInfo)
        return error
    }
}

// MARK: - Two-Factor Models -

/// How Apple should deliver a two-factor verification code.
@objc(ALTTwoFactorMethod)
public enum TwoFactorMethod: Int
{
    /// Push a code to the user's other signed-in Apple devices.
    case trustedDevice = 0
    
    /// Text a code to one of the account's trusted phone numbers.
    case sms
    
    /// Call one of the account's trusted phone numbers and read the code out.
    case voice
}

/// What the handler is currently being asked to do.
@objc(ALTTwoFactorStep)
public enum TwoFactorStep: Int
{
    /// Nothing has been sent yet: let the user pick how they want to receive a code.
    case selectMethod = 0
    
    /// A code was sent via `activeMethod`: prompt the user to enter it.
    case enterCode
}

@objc(ALTTwoFactorAction)
public enum TwoFactorAction: Int
{
    case requestTrustedDevice = 0
    case requestSMS
    case requestVoice
    case submitCode
    case cancel
    case fail
}

@objc(ALTTrustedPhoneNumber)
public class TrustedPhoneNumber: NSObject
{
    /// Identifier Apple uses to refer to this number ("phoneNumber.id").
    @objc public let identifier: String
    
    /// Masked display string, e.g. "+1 (•••) •••-••12".
    @objc public let displayNumber: String
    
    @objc public init(identifier: String, displayNumber: String)
    {
        self.identifier = identifier
        self.displayNumber = displayNumber
        super.init()
    }
    
    public override var description: String {
        return "<ALTTrustedPhoneNumber \(self.identifier): \(self.displayNumber)>"
    }
}

@objc(ALTTwoFactorRequest)
public class TwoFactorRequest: NSObject
{
    @objc public internal(set) var step: TwoFactorStep = .selectMethod
    
    /// The method Apple suggested (trusted device if the account has one signed in, otherwise SMS).
    @objc public internal(set) var preferredMethod: TwoFactorMethod = .trustedDevice
    
    /// The method the most recent code was sent with. Only meaningful for `.enterCode`.
    @objc public internal(set) var activeMethod: TwoFactorMethod = .trustedDevice
    
    /// All trusted phone numbers on the account (may be empty).
    @objc public internal(set) var phoneNumbers: [TrustedPhoneNumber] = []
    
    /// Which phone number the last SMS/voice code went to, if any.
    @objc public internal(set) var activePhoneID: String?
    
    /// Set when a previous attempt failed (e.g. wrong code), so the UI can explain why it's asking again.
    @objc public internal(set) var errorMessage: String?
    
    /// Whether the user can choose trusted device as a delivery method for this sign-in.
    @objc public internal(set) var supportsTrustedDevice: Bool = false
    
    public override var description: String {
        return "<ALTTwoFactorRequest step: \(self.step.rawValue) active: \(self.activeMethod.rawValue) phones: \(self.phoneNumbers) error: \(self.errorMessage ?? "nil")>"
    }
}

@objc(ALTTwoFactorResponse)
public class TwoFactorResponse: NSObject
{
    @objc public let action: TwoFactorAction
    @objc public internal(set) var phoneID: String?
    @objc public internal(set) var code: String?
    @objc public internal(set) var error: NSError?
    
    private init(action: TwoFactorAction)
    {
        self.action = action
        super.init()
    }
    
    @objc public static func requestTrustedDevice() -> TwoFactorResponse
    {
        return TwoFactorResponse(action: .requestTrustedDevice)
    }
    
    @objc public static func requestSMS(phoneID: String?) -> TwoFactorResponse
    {
        let response = TwoFactorResponse(action: .requestSMS)
        response.phoneID = phoneID
        return response
    }
    
    @objc public static func requestVoice(phoneID: String?) -> TwoFactorResponse
    {
        let response = TwoFactorResponse(action: .requestVoice)
        response.phoneID = phoneID
        return response
    }
    
    @objc public static func submitCode(_ code: String) -> TwoFactorResponse
    {
        let response = TwoFactorResponse(action: .submitCode)
        response.code = code
        return response
    }
    
    @objc public static func cancel() -> TwoFactorResponse
    {
        return TwoFactorResponse(action: .cancel)
    }
    
    @objc public static func fail(error: NSError) -> TwoFactorResponse
    {
        let response = TwoFactorResponse(action: .fail)
        response.error = error
        return response
    }
}

public typealias TwoFactorHandler = (TwoFactorRequest, @escaping (TwoFactorResponse) -> Void) -> Void

/// Mutable bookkeeping for one in-flight two-factor sign-in.
private final class TwoFactorState
{
    let dsid: String
    let idmsToken: String
    let anisetteData: ALTAnisetteData
    var phoneNumbers: [TrustedPhoneNumber]
    let preferredMethod: TwoFactorMethod
    let supportsTrustedDevice: Bool
    
    var activeMethod: TwoFactorMethod = .trustedDevice
    var activePhoneID: String?
    var hasActiveMethod = false
    
    init(dsid: String, idmsToken: String, anisetteData: ALTAnisetteData, phoneNumbers: [TrustedPhoneNumber], preferredMethod: TwoFactorMethod, supportsTrustedDevice: Bool)
    {
        self.dsid = dsid
        self.idmsToken = idmsToken
        self.anisetteData = anisetteData
        self.phoneNumbers = phoneNumbers
        self.preferredMethod = preferredMethod
        self.supportsTrustedDevice = supportsTrustedDevice
    }
}

public extension ALTAppleAPI
{
    /// Legacy entry point: trusted-device codes only. Kept so existing callers continue to work.
    @objc func authenticate(appleID: String,
                            password: String,
                            anisetteData: ALTAnisetteData,
                            verificationHandler: ((@escaping (String?) -> Void) -> Void)?,
                            completionHandler: @escaping (ALTAccount?, ALTAppleAPISession?, Error?) -> Void)
    {
        var twoFactorHandler: TwoFactorHandler?
        
        if let verificationHandler
        {
            // Old callers only understand "enter the code sent to your devices", so adapt that onto the
            // multi-method flow: always use a trusted device, ask for the code once, and don't retry.
            twoFactorHandler = { (request, completion) in
                if request.errorMessage != nil
                {
                    completion(.fail(error: ALTAppleAPIError(.incorrectVerificationCode) as NSError))
                    return
                }
                
                switch request.step
                {
                case .selectMethod:
                    completion(.requestTrustedDevice())
                    
                case .enterCode:
                    verificationHandler { (verificationCode) in
                        if let verificationCode
                        {
                            completion(.submitCode(verificationCode))
                        }
                        else
                        {
                            completion(.fail(error: ALTAppleAPIError(.requiresTwoFactorAuthentication) as NSError))
                        }
                    }
                }
            }
        }
        
        self.authenticate(appleID: appleID, password: password, anisetteData: anisetteData, twoFactorHandler: twoFactorHandler, completionHandler: completionHandler)
    }
    
    /// Signs in, supporting every verification method Apple offers: trusted-device codes, SMS and voice call
    /// to any trusted phone number. `twoFactorHandler` is called (possibly several times) while 2FA is pending.
    @objc func authenticate(appleID unsanitizedAppleID: String,
                            password: String,
                            anisetteData: ALTAnisetteData,
                            twoFactorHandler: TwoFactorHandler?,
                            completionHandler: @escaping (ALTAccount?, ALTAppleAPISession?, Error?) -> Void)
    {
        // Authenticating only works with lowercase email address, even if Apple ID contains capital letters.
        let sanitizedAppleID = unsanitizedAppleID.lowercased()
        
        do
        {
            let clientDictionary = [
                "bootstrap": true,
                "icscrec": true,
                "pbe": false,
                "prkgen": true,
                "svct": "iCloud",
                "loc": Locale.current.identifier,
                "X-Apple-Locale": Locale.current.identifier,
                "X-Apple-I-MD": anisetteData.oneTimePassword,
                "X-Apple-I-MD-M": anisetteData.machineID,
                "X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier,
                "X-Apple-I-MD-LU": anisetteData.localUserID,
                "X-Apple-I-MD-RINFO": anisetteData.routingInfo,
                "X-Apple-I-SRL-NO": anisetteData.deviceSerialNumber,
                "X-Apple-I-Client-Time": self.dateFormatter.string(from: anisetteData.date),
                "X-Apple-I-TimeZone": TimeZone.current.abbreviation() ?? "PST",
            ] as [String: Any]
            
            let context = GSAContext(username: sanitizedAppleID, password: password)
            guard let publicKey = context.start() else { throw ALTAppleAPIError(.authenticationHandshakeFailed) }
            
            let parameters = [
                "A2k": publicKey,
                "cpd": clientDictionary,
                "ps": ["s2k", "s2k_fo"],
                "o": "init",
                "u": sanitizedAppleID
            ] as [String: Any]
            
            self.sendAuthenticationRequest(parameters: parameters, anisetteData: anisetteData) { (result) in
                do
                {
                    let responseDictionary = try result.get()

                    guard let c = responseDictionary["c"] as? String,
                          let salt = responseDictionary["s"] as? Data,
                          let iterations = responseDictionary["i"] as? Int,
                          let serverPublicKey = responseDictionary["B"] as? Data
                    else { throw URLError(.badServerResponse) }
                    
                    context.salt = salt
                    context.serverPublicKey = serverPublicKey
                    
                    let sp = responseDictionary["sp"] as? String
                    let isHexadecimal = (sp == "s2k_fo")                    
                    
                    guard let verificationMessage = context.makeVerificationMessage(iterations: iterations, isHexadecimal: isHexadecimal) else {
                        throw ALTAppleAPIError(.authenticationHandshakeFailed)
                    }
                    
                    let parameters = [
                        "c": c,
                        "cpd": clientDictionary,
                        "M1": verificationMessage,
                        "o": "complete",
                        "u": sanitizedAppleID
                    ] as [String: Any]
                    
                    self.sendAuthenticationRequest(parameters: parameters, anisetteData: anisetteData) { (result) in
                        do
                        {
                            let responseDictionary = try result.get()
                            
                            guard let serverVerificationMessage = responseDictionary["M2"] as? Data,
                                  let serverDictionary = responseDictionary["spd"] as? Data,
                                  let statusDictionary = responseDictionary["Status"] as? [String: Any]
                            else { throw URLError(.badServerResponse) }
                            
                            guard context.verifyServerVerificationMessage(serverVerificationMessage) else { throw ALTAppleAPIError(.authenticationHandshakeFailed) }
                            guard let decryptedData = serverDictionary.decryptedCBC(context: context) else { throw ALTAppleAPIError(.authenticationHandshakeFailed) }
                            
                            guard let decryptedDictionary = try PropertyListSerialization.propertyList(from: decryptedData, format: nil) as? [String: Any],
                                  let dsid = decryptedDictionary["adsid"] as? String,
                                  let idmsToken = decryptedDictionary["GsIdmsToken"] as? String
                            else { throw URLError(.badServerResponse) }
                            
                            context.dsid = dsid
                            
                            let authType = statusDictionary["au"] as? String
                            if self.isTwoFactorAuthType(authType)
                            {
                                guard let twoFactorHandler else { throw ALTAppleAPIError(.requiresTwoFactorAuthentication) }
                                
                                let isTrustedDevice = (authType == "trustedDeviceSecondaryAuth" || authType == "trustedDevice")
                                
                                var phoneNumbers = self.parseTrustedPhoneNumbers(from: responseDictionary)
                                if phoneNumbers.isEmpty
                                {
                                    phoneNumbers = self.parseTrustedPhoneNumbers(from: statusDictionary)
                                }
                                
                                let state = TwoFactorState(dsid: dsid,
                                                           idmsToken: idmsToken,
                                                           anisetteData: anisetteData,
                                                           phoneNumbers: phoneNumbers,
                                                           preferredMethod: isTrustedDevice ? .trustedDevice : .sms,
                                                           supportsTrustedDevice: isTrustedDevice)
                                
                                self.performTwoFactor(state: state, handler: twoFactorHandler) { (result) in
                                    switch result
                                    {
                                    case .failure(let error): completionHandler(nil, nil, error)
                                    case .success:
                                        // We've successfully signed-in with two-factor, so restart authentication (which will now succeed).
                                        self.authenticate(appleID: unsanitizedAppleID, password: password, anisetteData: anisetteData, twoFactorHandler: twoFactorHandler, completionHandler: completionHandler)
                                    }
                                }
                                return
                            }
                            
                            switch authType
                            {
                            default:
                                guard let sessionKey = decryptedDictionary["sk"] as? Data,
                                      let c = decryptedDictionary["c"] as? Data
                                else { throw URLError(.badServerResponse) }
                                
                                context.sessionKey = sessionKey
                                
                                let app = "com.apple.gs.xcode.auth"
                                guard let checksum = context.makeChecksum(appName: app) else { throw ALTAppleAPIError(.authenticationHandshakeFailed) }
                                
                                let parameters = [
                                    "app": [app],
                                    "c": c,
                                    "checksum": checksum,
                                    "cpd": clientDictionary,
                                    "o": "apptokens",
                                    "t": idmsToken,
                                    "u": dsid
                                ] as [String: Any]
                                
                                self.fetchAuthToken(app: app, parameters: parameters, context: context, anisetteData: anisetteData) { (result) in
                                    switch result
                                    {
                                    case .failure(let error): completionHandler(nil, nil, error)
                                    case .success(let token):
                                        
                                        let session = ALTAppleAPISession(dsid: dsid, authToken: token, anisetteData: anisetteData)
                                        self.fetchAccount(session: session) { (result) in
                                            switch result
                                            {
                                            case .failure(let error): completionHandler(nil, nil, error)
                                            case .success(let account): completionHandler(account, session, nil)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        catch
                        {
                            completionHandler(nil, nil, error)
                        }
                    }
                }
                catch
                {
                    completionHandler(nil, nil, error)
                }
            }
        }
        catch
        {
            completionHandler(nil, nil, error)
        }
    }
}

private extension ALTAppleAPI
{
    func fetchAuthToken(app: String, parameters: [String: Any], context: GSAContext, anisetteData: ALTAnisetteData, completionHandler: @escaping (Result<String, Error>) -> Void)
    {
        self.sendAuthenticationRequest(parameters: parameters, anisetteData: anisetteData) { (result) in
            do
            {
                let responseDictionary = try result.get()
                
                guard let encryptedToken = responseDictionary["et"] as? Data else { throw URLError(.badServerResponse) }
                guard let token = encryptedToken.decryptedGCM(context: context) else { throw ALTAppleAPIError(.authenticationHandshakeFailed) }
                
                guard let tokensDictionary = try PropertyListSerialization.propertyList(from: token, format: nil) as? [String: Any] else {
                    throw URLError(.badServerResponse)
                }
                
                guard let appTokens = tokensDictionary["t"] as? [String: Any],
                      let tokens = appTokens[app] as? [String: Any],
                      let authToken = tokens["token"] as? String
                else { throw URLError(.badServerResponse) }
                
                completionHandler(.success(authToken))
            }
            catch
            {
                completionHandler(.failure(error))
            }
        }
    }
    
    // MARK: Two-Factor Flow
    
    func isTwoFactorAuthType(_ authType: String?) -> Bool
    {
        guard let authType else { return false }
        return ["trustedDeviceSecondaryAuth", "trustedDevice", "secondaryAuth", "sms", "voice", "phone"].contains(authType)
    }
    
    /// Drives the whole 2FA exchange: asks the handler what to do, performs it, and loops until the code is
    /// accepted, the user cancels, or something unrecoverable happens.
    func performTwoFactor(state: TwoFactorState, handler: @escaping TwoFactorHandler, completionHandler: @escaping (Result<Void, Error>) -> Void)
    {
        var finished = false
        
        func finish(_ result: Result<Void, Error>)
        {
            guard !finished else { return }
            finished = true
            completionHandler(result)
        }
        
        func prompt(step: TwoFactorStep, errorMessage: String? = nil)
        {
            let request = TwoFactorRequest()
            request.step = step
            request.preferredMethod = state.preferredMethod
            request.activeMethod = state.activeMethod
            request.phoneNumbers = state.phoneNumbers
            request.activePhoneID = state.activePhoneID
            request.errorMessage = errorMessage
            request.supportsTrustedDevice = state.supportsTrustedDevice
            
            handler(request) { (response) in
                switch response.action
                {
                case .cancel:
                    finish(.failure(ALTAppleAPIError(.verificationCancelled)))
                    
                case .fail:
                    finish(.failure((response.error as Error?) ?? ALTAppleAPIError(.verificationFailed)))
                    
                case .requestTrustedDevice:
                    self.sendTrustedDeviceCodeRequest(state: state) { (error) in
                        if let error
                        {
                            // Let the user pick another way to receive a code instead of failing the whole sign-in.
                            prompt(step: .selectMethod, errorMessage: error.localizedDescription)
                            return
                        }
                        
                        state.activeMethod = .trustedDevice
                        state.activePhoneID = nil
                        state.hasActiveMethod = true
                        prompt(step: .enterCode)
                    }
                    
                case .requestSMS, .requestVoice:
                    let method: TwoFactorMethod = (response.action == .requestSMS) ? .sms : .voice
                    
                    self.sendPhoneCodeRequest(method: method, phoneID: response.phoneID, state: state) { (result) in
                        switch result
                        {
                        case .failure(let error):
                            prompt(step: .selectMethod, errorMessage: error.localizedDescription)
                            
                        case .success(let phoneID):
                            state.activeMethod = method
                            state.activePhoneID = phoneID
                            state.hasActiveMethod = true
                            prompt(step: .enterCode)
                        }
                    }
                    
                case .submitCode:
                    guard state.hasActiveMethod else {
                        // The handler skipped choosing a delivery method, so there's nothing to verify against.
                        return prompt(step: .selectMethod)
                    }
                    
                    let code = (response.code ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !code.isEmpty else { return prompt(step: .enterCode) }
                    
                    self.validateTwoFactorCode(code, state: state) { (result) in
                        switch result
                        {
                        case .success(.accepted): finish(.success(()))
                        case .success(.retry(let message)): prompt(step: .enterCode, errorMessage: message)
                        case .failure(let error): finish(.failure(error))
                        }
                    }
                    
                @unknown default:
                    finish(.failure(ALTAppleAPIError(.verificationFailed)))
                }
            }
        }
        
        prompt(step: .selectMethod)
    }
    
    // MARK: Requests
    
    enum CodeValidationResult
    {
        case accepted
        case retry(message: String)
    }
    
    /// The phone endpoints answer with Apple's "buddyml" UI markup, so they need a slightly different Accept/Content-Type.
    func makePhoneRequest(url: URL, state: TwoFactorState) -> URLRequest
    {
        var request = self.makeTwoFactorCodeRequest(url: url, dsid: state.dsid, idmsToken: state.idmsToken, anisetteData: state.anisetteData)
        request.setValue("application/x-buddyml", forHTTPHeaderField: "Accept")
        request.setValue("application/x-plist", forHTTPHeaderField: "Content-Type")
        request.setValue("close", forHTTPHeaderField: "Connection")
        return request
    }
    
    func sendTrustedDeviceCodeRequest(state: TwoFactorState, completionHandler: @escaping (Error?) -> Void)
    {
        let url = URL(string: "https://gsa.apple.com/auth/verify/trusteddevice")!
        let request = self.makeTwoFactorCodeRequest(url: url, dsid: state.dsid, idmsToken: state.idmsToken, anisetteData: state.anisetteData)
        
        self.sendGSARequest(request) { (result) in
            switch result
            {
            case .failure(let error): completionHandler(error)
            case .success(let (data, response)):
                if let alertError = self.errorForXMLUIAlert(in: data)
                {
                    return completionHandler(alertError)
                }
                
                guard (200 ..< 300).contains(response.statusCode) else {
                    let message = String(format: NSLocalizedString("Couldn't send a code to your devices (HTTP %d).", comment: ""), response.statusCode)
                    return completionHandler(ALTAppleAPIError(.verificationFailed, userInfo: [NSLocalizedDescriptionKey: message]))
                }
                
                completionHandler(nil)
            }
        }
    }
    
    func sendPhoneCodeRequest(method: TwoFactorMethod, phoneID requestedPhoneID: String?, state: TwoFactorState, completionHandler: @escaping (Result<String, Error>) -> Void)
    {
        let mode = (method == .voice) ? "voice" : "sms"
        
        var phoneID = (requestedPhoneID ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if phoneID.isEmpty
        {
            // Apple's primary trusted number.
            phoneID = state.phoneNumbers.first?.identifier ?? "1"
        }
        
        let url = URL(string: "https://gsa.apple.com/auth/verify/phone/put?mode=\(mode)")!
        var request = self.makePhoneRequest(url: url, state: state)
        request.httpMethod = "POST"
        
        do
        {
            let body = ["serverInfo": ["mode": mode, "phoneNumber.id": phoneID]]
            request.httpBody = try PropertyListSerialization.data(fromPropertyList: body, format: .xml, options: 0)
        }
        catch
        {
            return completionHandler(.failure(error))
        }
        
        self.sendGSARequest(request) { (result) in
            switch result
            {
            case .failure(let error): completionHandler(.failure(error))
            case .success(let (data, response)):
                if let alertError = self.errorForXMLUIAlert(in: data)
                {
                    return completionHandler(.failure(alertError))
                }
                
                let responseDictionary = self.propertyListOrJSON(from: data)
                let errorCode = self.integerValue(responseDictionary?["ec"])
                let errorMessage = responseDictionary?["em"] as? String
                
                if self.isRateLimitError(code: errorCode, statusCode: response.statusCode)
                {
                    return completionHandler(.failure(self.rateLimitError(message: errorMessage)))
                }
                
                if errorCode != 0
                {
                    let message = errorMessage ?? String(format: NSLocalizedString("Couldn't send a code (%d).", comment: ""), errorCode)
                    return completionHandler(.failure(ALTAppleAPIError(.verificationFailed, userInfo: [NSLocalizedDescriptionKey: message])))
                }
                
                guard response.statusCode == 200 else {
                    let message = String(format: NSLocalizedString("Couldn't send a code (HTTP %d).", comment: ""), response.statusCode)
                    return completionHandler(.failure(ALTAppleAPIError(.verificationFailed, userInfo: [NSLocalizedDescriptionKey: message])))
                }
                
                // Apple echoes back the phone it actually used, and often a masked version of the number.
                let string = String(data: data, encoding: .utf8)
                let usedPhoneID = self.firstMatch(of: "(?<=phoneNumber\\.id=\")[^\"]+", in: string) ?? phoneID
                
                let obfuscated = self.firstMatch(of: "(?<=obfuscatedNumber=\")[^\"]+", in: string)
                    ?? self.firstMatch(of: "(?<=numberWithDialCode=\")[^\"]+", in: string)
                
                if let obfuscated, !state.phoneNumbers.contains(where: { $0.identifier == usedPhoneID })
                {
                    state.phoneNumbers.append(TrustedPhoneNumber(identifier: usedPhoneID, displayNumber: obfuscated))
                }
                
                completionHandler(.success(usedPhoneID))
            }
        }
    }
    
    func validateTwoFactorCode(_ code: String, state: TwoFactorState, completionHandler: @escaping (Result<CodeValidationResult, Error>) -> Void)
    {
        let isTrustedDevice = (state.activeMethod == .trustedDevice)
        
        var request: URLRequest
        if isTrustedDevice
        {
            let url = URL(string: "https://gsa.apple.com/grandslam/GsService2/validate")!
            request = self.makeTwoFactorCodeRequest(url: url, dsid: state.dsid, idmsToken: state.idmsToken, anisetteData: state.anisetteData)
            request.setValue(code, forHTTPHeaderField: "security-code")
        }
        else
        {
            let mode = (state.activeMethod == .voice) ? "voice" : "sms"
            let phoneID = state.activePhoneID ?? state.phoneNumbers.first?.identifier ?? "1"
            
            let url = URL(string: "https://gsa.apple.com/auth/verify/phone/securitycode?referrer=/auth/verify/phone/put")!
            request = self.makePhoneRequest(url: url, state: state)
            request.httpMethod = "POST"
            
            do
            {
                let body = [
                    "securityCode": ["code": code],
                    "serverInfo": ["mode": mode, "phoneNumber.id": phoneID]
                ]
                request.httpBody = try PropertyListSerialization.data(fromPropertyList: body, format: .xml, options: 0)
            }
            catch
            {
                return completionHandler(.failure(error))
            }
        }
        
        let incorrectCodeMessage = NSLocalizedString("Incorrect verification code. Please try again.", comment: "")
        
        self.sendGSARequest(request) { (result) in
            switch result
            {
            case .failure(let error): completionHandler(.failure(error))
            case .success(let (data, httpResponse)):
                let statusCode = httpResponse.statusCode
                
                let responseDictionary = self.propertyListOrJSON(from: data)
                let statusDictionary = responseDictionary?["Status"] as? [String: Any]
                let errorCode = self.integerValue(responseDictionary?["ec"])
                
                let alert = self.parseXMLUIAlert(in: data)
                let errorMessage = (responseDictionary?["em"] as? String) ?? (statusDictionary?["em"] as? String) ?? alert.message ?? alert.title
                
                if self.isRateLimitError(code: errorCode, statusCode: statusCode)
                {
                    return completionHandler(.failure(self.rateLimitError(message: errorMessage)))
                }
                
                if errorCode == -21669
                {
                    return completionHandler(.success(.retry(message: errorMessage ?? incorrectCodeMessage)))
                }
                
                if errorCode != 0
                {
                    let description = "\(errorMessage ?? NSLocalizedString("Verification error", comment: "")) (\(errorCode))"
                    return completionHandler(.failure(ALTAppleAPIError(.unknown, userInfo: [NSLocalizedDescriptionKey: description])))
                }
                
                if alert.title != nil || alert.message != nil
                {
                    let message = alert.message ?? errorMessage ?? alert.title ?? NSLocalizedString("Verification failed", comment: "")
                    return completionHandler(.failure(ALTAppleAPIError(.verificationFailed, userInfo: [NSLocalizedDescriptionKey: message])))
                }
                
                guard statusCode == 200 else {
                    return completionHandler(.success(.retry(message: errorMessage ?? incorrectCodeMessage)))
                }
                
                if !isTrustedDevice
                {
                    // A phone code is only accepted if Apple hands back its "PE" token.
                    let hasPEToken = httpResponse.allHeaderFields.keys.contains { (key) in
                        guard let key = key as? String else { return false }
                        return key.caseInsensitiveCompare("x-apple-pe-token") == .orderedSame
                    }
                    
                    guard hasPEToken else {
                        return completionHandler(.success(.retry(message: errorMessage ?? incorrectCodeMessage)))
                    }
                }
                
                completionHandler(.success(.accepted))
            }
        }
    }
    
    // MARK: Parsing
    
    func isRateLimitError(code: Int, statusCode: Int) -> Bool
    {
        // -21668: too many attempts, -20102: too many codes requested, -22411: rate limited.
        return (code == -21668 || code == -20102 || code == -22411 || statusCode == 429)
    }
    
    func rateLimitError(message: String?) -> Error
    {
        var userInfo = [String: Any]()
        if let message, !message.isEmpty
        {
            userInfo[NSLocalizedDescriptionKey] = message
        }
        
        return ALTAppleAPIError(.tooManyVerificationAttempts, userInfo: userInfo)
    }
    
    // Same for NSString or NSNumber.
    func integerValue(_ value: Any?) -> Int
    {
        switch value
        {
        case let number as NSNumber: return number.intValue
        case let string as String: return Int(string) ?? 0
        default: return 0
        }
    }
    
    func propertyListOrJSON(from data: Data) -> [String: Any]?
    {
        if let object = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        {
            return object
        }
        
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }
    
    func firstMatch(of pattern: String, in string: String?) -> String?
    {
        guard let string, let expression = try? NSRegularExpression(pattern: pattern) else { return nil }
        
        let range = NSRange(string.startIndex ..< string.endIndex, in: string)
        guard let match = expression.firstMatch(in: string, range: range), let matchRange = Range(match.range, in: string) else { return nil }
        return String(string[matchRange])
    }
    
    /// Apple reports some failures as a buddyml `<alert title="…" message="…">` rather than a status code.
    func parseXMLUIAlert(in data: Data) -> (title: String?, message: String?)
    {
        guard let string = String(data: data, encoding: .utf8), !string.contains("<pinView") else { return (nil, nil) }
        guard let tag = self.firstMatch(of: "<alert(?![^>]*\\bid=)[^>]*>", in: string) else { return (nil, nil) }
        
        let title = self.firstMatch(of: "(?<=title=\")[^\"]+", in: tag)
        let message = self.firstMatch(of: "(?<=message=\")[^\"]+", in: tag)
        return (title, message)
    }
    
    func errorForXMLUIAlert(in data: Data) -> Error?
    {
        let alert = self.parseXMLUIAlert(in: data)
        guard let text = alert.message ?? alert.title else { return nil }
        
        return ALTAppleAPIError(.verificationFailed, userInfo: [NSLocalizedDescriptionKey: text])
    }
    
    func parseTrustedPhoneNumbers(from dictionary: [String: Any]) -> [TrustedPhoneNumber]
    {
        var list = (dictionary["trustedPhoneNumbers"] ?? dictionary["phoneNumbers"]) as? [Any] ?? []
        if list.isEmpty, let phoneNumber = dictionary["phoneNumber"] as? [String: Any]
        {
            list = [phoneNumber]
        }
        
        return list.compactMap { (item) in
            guard let item = item as? [String: Any] else { return nil }
            
            let identifier = "\(item["id"] ?? "")".trimmingCharacters(in: .whitespacesAndNewlines)
            guard !identifier.isEmpty else { return nil }
            
            var display = (item["numberWithDialCode"] as? String) ?? (item["obfuscatedNumber"] as? String)
            if display == nil, let lastTwoDigits = item["lastTwoDigits"]
            {
                display = "••\(lastTwoDigits)"
            }
            
            return TrustedPhoneNumber(identifier: identifier, displayNumber: display ?? "Phone \(identifier)")
        }
    }
    
    func fetchAccount(session: ALTAppleAPISession, completionHandler: @escaping (Result<ALTAccount, Error>) -> Void)
    {
        let url = URL(string: "viewDeveloper.action", relativeTo: self.baseURL)!
        
        self.sendRequest(with: url, additionalParameters: nil, session: session, team: nil) { (responseDictionary, requestError) in
            do
            {
                guard let responseDictionary = responseDictionary else { throw requestError ?? ALTAppleAPIError.unknown() }
                
                guard let account = try self.processResponse(responseDictionary, parseHandler: { () -> Any? in
                    guard let dictionary = responseDictionary["developer"] as? [String: Any] else { return nil }
                    let account = ALTAccount(responseDictionary: dictionary)
                    return account
                }, resultCodeHandler: nil) as? ALTAccount else {
                    throw ALTAppleAPIError.unknown()
                }
                
                completionHandler(.success(account))
            }
            catch
            {
                completionHandler(.failure(error))
            }
        }
    }
}

private extension ALTAppleAPI
{
    // Apple's servers reject outdated client identities, so use the same modern AuthKit identity for every request.
    static let userAgent = "AuthKit/1 (Macintosh; OS X 26.5.2) (com.apple.dt.Xcode/26.0)"
    
    func sendGSARequest(_ request: URLRequest, completionHandler: @escaping (Result<(Data, HTTPURLResponse), Error>) -> Void)
    {
        // Create a new session, and limit the maximum connections to just one at a time.
        // Otherwise, Apple's servers may reject connections with more than 2 requests.
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpMaximumConnectionsPerHost = 1
        
        let session = URLSession(configuration: configuration)
        defer { session.finishTasksAndInvalidate() }
        
        let dataTask = session.dataTask(with: request) { (data, response, error) in
            do
            {
                guard let data = data, let httpResponse = response as? HTTPURLResponse else { throw error ?? ALTAppleAPIError.unknown() }
                
                #if LOG_GSA
                // Only log the response, NOT the request, because request headers contain the identity token and anisette data.
                let body = String(data: data, encoding: .utf8) ?? "<\(data.count) bytes>"
                print("GSA Request Body:", body)
                #endif
                
                completionHandler(.success((data, httpResponse)))
            }
            catch
            {
                completionHandler(.failure(error))
            }
        }
        
        dataTask.resume()
    }
    
    func sendAuthenticationRequest(parameters requestParameters: [String: Any], anisetteData: ALTAnisetteData, completionHandler: @escaping (Result<[String: Any], Error>) -> Void)
    {
        do
        {
            let requestURL = URL(string: "https://gsa.apple.com/grandslam/GsService2")!
            
            let parameters = [
                "Header": ["Version": "1.0.1"],
                "Request": requestParameters
            ]
            
            let httpHeaders = [
                "Content-Type": "text/x-xml-plist",
                "X-MMe-Client-Info": anisetteData.deviceDescription,
                "Accept": "*/*",
                "User-Agent": ALTAppleAPI.userAgent
            ]
            
            let bodyData = try PropertyListSerialization.data(fromPropertyList: parameters, format: .xml, options: 0)
            
            var request = URLRequest(url: requestURL)
            request.httpMethod = "POST"
            request.httpBody = bodyData
            httpHeaders.forEach { request.addValue($0.value, forHTTPHeaderField: $0.key) }
            
            self.sendGSARequest(request) { (result) in
                do
                {
                    let (data, _) = try result.get()
                    
                    guard let responseDictionary = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                          let dictionary = responseDictionary["Response"] as? [String: Any],
                          let status = dictionary["Status"] as? [String: Any]
                    else { throw URLError(.badServerResponse) }
                                        
                    let errorCode = status["ec"] as? Int ?? 0
                    guard errorCode != 0 else { return completionHandler(.success(dictionary)) }
                    
                    switch errorCode
                    {
                    case -20101, -22406: throw ALTAppleAPIError(.incorrectCredentials)
                    case -22421: throw ALTAppleAPIError(.invalidAnisetteData)
                    default:
                        guard let errorDescription = status["em"] as? String else { throw ALTAppleAPIError.unknown() }
                        
                        let localizedDescription = errorDescription + " (\(errorCode))"
                        throw NSError(domain: ALTUnderlyingAppleAPIErrorDomain, code: errorCode, userInfo: [NSLocalizedDescriptionKey: localizedDescription])
                    }
                }
                catch
                {
                    completionHandler(.failure(error))
                }
            }
        }
        catch
        {
            completionHandler(.failure(error))
        }
    }
    
    func makeTwoFactorCodeRequest(url: URL,
                                  dsid: String,
                                  idmsToken: String,
                                  anisetteData: ALTAnisetteData) -> URLRequest
    {
        let identityToken = dsid + ":" + idmsToken
        
        let identityTokenData = identityToken.data(using: .utf8)!
        let encodedIdentityToken = identityTokenData.base64EncodedString()
        
        let httpHeaders = [
            "Accept": "application/x-buddyml",
            "Accept-Language": "en-us",
            "Content-Type": "application/x-plist",
            "User-Agent": ALTAppleAPI.userAgent,
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Apple-Identity-Token": encodedIdentityToken,
            "X-Apple-I-MD-M": anisetteData.machineID,
            "X-Apple-I-MD": anisetteData.oneTimePassword,
            "X-Apple-I-MD-LU": anisetteData.localUserID,
            "X-Apple-I-MD-RINFO": "\(anisetteData.routingInfo)",
            "X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier,
            "X-MMe-Client-Info": anisetteData.deviceDescription,
            "X-Apple-I-Client-Time": self.dateFormatter.string(from: anisetteData.date),
            "X-Apple-Locale": anisetteData.locale.identifier,
            "X-Apple-I-TimeZone": anisetteData.timeZone.abbreviation() ?? "PST",
            "X-Apple-I-SRL-NO": anisetteData.deviceSerialNumber
        ]
        
        var request = URLRequest(url: url)
        httpHeaders.forEach { request.addValue($0.value, forHTTPHeaderField: $0.key) }
        
        return request
    }
}
