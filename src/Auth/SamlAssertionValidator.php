<?php

declare(strict_types=1);

namespace authlib\Auth\Auth;

use authlib\Auth\Contracts\TokenValidatorInterface;
use DOMDocument;
use DOMXPath;
use stdClass;
use DateTime;
use DateTimeZone;

/**
 * SAML Assertion Validator
 * 
 * Validates SAML 2.0 assertions with signature verification and claims extraction.
 * Supports both base64 encoded and raw XML assertions.
 */
class SamlAssertionValidator implements TokenValidatorInterface
{
    private const SAML_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';
    private const XMLDSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';
    
    private ?string $certificate = null;
    private int $clockSkewSeconds = 60;

    public function __construct(
        private string $issuer,
        private string $audience,
        private string $certificatePath
    ) {
        $this->loadCertificate();
    }

    /**
     * Validate SAML assertion and return claims
     */
    public function validate(string $assertion): stdClass
    {
        // Decode if base64 encoded
        if ($this->isBase64Encoded($assertion)) {
            $assertion = base64_decode($assertion);
        }

        $doc = $this->parseXml($assertion);
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('saml', self::SAML_NS);
        $xpath->registerNamespace('ds', self::XMLDSIG_NS);

        // Validate assertion structure
        $assertionNode = $xpath->query('//saml:Assertion')->item(0);
        if (!$assertionNode) {
            throw new \Exception('No SAML assertion found in response');
        }

        // Verify signature if present
        $this->verifySignature($doc, $xpath);

        // Validate conditions (time, audience, etc.)
        $this->validateConditions($doc, $xpath);

        // Extract claims
        return $this->extractClaims($doc, $xpath);
    }

    /**
     * Check if assertion is valid without throwing exceptions
     */
    public function isValid(string $assertion): bool
    {
        try {
            $this->validate($assertion);
            return true;
        } catch (\Exception) {
            return false;
        }
    }

    /**
     * Get the expected issuer for this validator
     */
    public function getAcceptedIssuer(): ?string
    {
        return $this->issuer;
    }

    /**
     * Get the expected audience for this validator
     */
    public function getAcceptedAudience(): ?string
    {
        return $this->audience;
    }

    /**
     * Set clock skew tolerance in seconds
     */
    public function setClockSkew(int $seconds): void
    {
        $this->clockSkewSeconds = $seconds;
    }

    /**
     * Load certificate from file
     */
    private function loadCertificate(): void
    {
        if (!file_exists($this->certificatePath)) {
            throw new \Exception("Certificate file not found: {$this->certificatePath}");
        }

        $certContent = file_get_contents($this->certificatePath);
        if ($certContent === false) {
            throw new \Exception("Failed to read certificate file: {$this->certificatePath}");
        }

        // Clean up certificate format
        $certContent = str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'], '', $certContent);
        $certContent = preg_replace('/\s+/', '', $certContent);
        
        $this->certificate = $certContent;
    }

    /**
     * Check if string is base64 encoded
     */
    private function isBase64Encoded(string $data): bool
    {
        return base64_encode(base64_decode($data, true)) === $data;
    }

    /**
     * Parse XML assertion
     */
    private function parseXml(string $xml): DOMDocument
    {
        $doc = new DOMDocument();
        $doc->preserveWhiteSpace = false;
        
        // Disable external entity loading for security
        libxml_use_internal_errors(true);
        $prevEntityLoader = libxml_disable_entity_loader(true);
        
        try {
            if (!$doc->loadXML($xml, LIBXML_NONET)) {
                $errors = libxml_get_errors();
                $errorMessages = array_map(fn($error) => $error->message, $errors);
                throw new \Exception('Invalid XML: ' . implode(', ', $errorMessages));
            }
        } finally {
            libxml_disable_entity_loader($prevEntityLoader);
            libxml_clear_errors();
        }

        return $doc;
    }

    /**
     * Verify XML signature
     */
    private function verifySignature(DOMDocument $doc, DOMXPath $xpath): void
    {
        $signatureNodes = $xpath->query('//ds:Signature');
        
        if ($signatureNodes->length === 0) {
            throw new \Exception('SAML assertion is not signed');
        }

        if ($signatureNodes->length > 1) {
            throw new \Exception('Multiple signatures found in SAML assertion');
        }

        $signatureNode = $signatureNodes->item(0);
        
        // Get signed info
        $signedInfo = $xpath->query('.//ds:SignedInfo', $signatureNode)->item(0);
        if (!$signedInfo) {
            throw new \Exception('SignedInfo not found in signature');
        }

        // Get signature value
        $signatureValueNode = $xpath->query('.//ds:SignatureValue', $signatureNode)->item(0);
        if (!$signatureValueNode) {
            throw new \Exception('SignatureValue not found');
        }

        $signatureValue = base64_decode(trim($signatureValueNode->nodeValue));

        // Canonicalize signed info
        $canonicalizedSignedInfo = $this->canonicalizeXml($signedInfo);

        // Verify signature using public key
        if (!$this->verifySignatureWithCertificate($canonicalizedSignedInfo, $signatureValue)) {
            throw new \Exception('SAML assertion signature verification failed');
        }
    }

    /**
     * Canonicalize XML for signature verification
     */
    private function canonicalizeXml(\DOMNode $node): string
    {
        return $node->C14N(true, false);
    }

    /**
     * Verify signature using certificate
     */
    private function verifySignatureWithCertificate(string $data, string $signature): bool
    {
        if (!$this->certificate) {
            throw new \Exception('No certificate loaded for signature verification');
        }

        $publicKey = "-----BEGIN CERTIFICATE-----\n" . 
                    chunk_split($this->certificate, 64, "\n") . 
                    "-----END CERTIFICATE-----";

        $key = openssl_pkey_get_public($publicKey);
        if (!$key) {
            throw new \Exception('Failed to load public key from certificate');
        }

        $result = openssl_verify($data, $signature, $key, OPENSSL_ALGO_SHA256);
        
        if ($result === -1) {
            throw new \Exception('Error verifying signature: ' . openssl_error_string());
        }

        return $result === 1;
    }

    /**
     * Validate assertion conditions (time bounds, audience, etc.)
     */
    private function validateConditions(DOMDocument $doc, DOMXPath $xpath): void
    {
        // Validate issuer
        $issuerNode = $xpath->query('//saml:Assertion/saml:Issuer')->item(0);
        if (!$issuerNode) {
            throw new \Exception('No issuer found in SAML assertion');
        }

        $actualIssuer = trim($issuerNode->nodeValue);
        if ($actualIssuer !== $this->issuer) {
            throw new \Exception("Invalid issuer. Expected: {$this->issuer}, Got: {$actualIssuer}");
        }

        // Validate conditions
        $conditionsNode = $xpath->query('//saml:Assertion/saml:Conditions')->item(0);
        if ($conditionsNode) {
            $this->validateTimeConditions($conditionsNode);
            $this->validateAudienceRestriction($xpath, $conditionsNode);
        }

        // Validate subject confirmation
        $this->validateSubjectConfirmation($xpath);
    }

    /**
     * Validate time-based conditions
     */
    private function validateTimeConditions(\DOMElement $conditionsNode): void
    {
        $now = new DateTime('now', new DateTimeZone('UTC'));
        $currentTime = $now->getTimestamp();

        // Check NotBefore
        if ($conditionsNode->hasAttribute('NotBefore')) {
            $notBefore = new DateTime($conditionsNode->getAttribute('NotBefore'));
            if ($currentTime < ($notBefore->getTimestamp() - $this->clockSkewSeconds)) {
                throw new \Exception('SAML assertion is not yet valid (NotBefore condition failed)');
            }
        }

        // Check NotOnOrAfter
        if ($conditionsNode->hasAttribute('NotOnOrAfter')) {
            $notOnOrAfter = new DateTime($conditionsNode->getAttribute('NotOnOrAfter'));
            if ($currentTime >= ($notOnOrAfter->getTimestamp() + $this->clockSkewSeconds)) {
                throw new \Exception('SAML assertion has expired (NotOnOrAfter condition failed)');
            }
        }
    }

    /**
     * Validate audience restriction
     */
    private function validateAudienceRestriction(DOMXPath $xpath, \DOMElement $conditionsNode): void
    {
        $audienceNodes = $xpath->query('.//saml:AudienceRestriction/saml:Audience', $conditionsNode);
        
        if ($audienceNodes->length === 0) {
            return; // No audience restriction
        }

        $validAudience = false;
        foreach ($audienceNodes as $audienceNode) {
            $audience = trim($audienceNode->nodeValue);
            if ($audience === $this->audience) {
                $validAudience = true;
                break;
            }
        }

        if (!$validAudience) {
            throw new \Exception("Invalid audience. Expected: {$this->audience}");
        }
    }

    /**
     * Validate subject confirmation
     */
    private function validateSubjectConfirmation(DOMXPath $xpath): void
    {
        $subjectConfirmationNodes = $xpath->query('//saml:Assertion/saml:Subject/saml:SubjectConfirmation');
        
        if ($subjectConfirmationNodes->length === 0) {
            throw new \Exception('No subject confirmation found in SAML assertion');
        }

        // At least one subject confirmation must be valid
        $validConfirmation = false;
        $now = new DateTime('now', new DateTimeZone('UTC'));

        foreach ($subjectConfirmationNodes as $confirmationNode) {
            $method = $confirmationNode->getAttribute('Method');
            
            // Check for bearer confirmation
            if ($method === 'urn:oasis:names:tc:SAML:2.0:cm:bearer') {
                $confirmationDataNode = $xpath->query('.//saml:SubjectConfirmationData', $confirmationNode)->item(0);
                
                if ($confirmationDataNode) {
                    // Validate NotOnOrAfter for subject confirmation
                    if ($confirmationDataNode->hasAttribute('NotOnOrAfter')) {
                        $notOnOrAfter = new DateTime($confirmationDataNode->getAttribute('NotOnOrAfter'));
                        if ($now->getTimestamp() < ($notOnOrAfter->getTimestamp() + $this->clockSkewSeconds)) {
                            $validConfirmation = true;
                            break;
                        }
                    } else {
                        $validConfirmation = true;
                        break;
                    }
                }
            }
        }

        if (!$validConfirmation) {
            throw new \Exception('No valid subject confirmation found');
        }
    }

    /**
     * Extract claims from SAML assertion
     */
    private function extractClaims(DOMDocument $doc, DOMXPath $xpath): stdClass
    {
        $claims = new stdClass();

        // Extract subject
        $subjectNode = $xpath->query('//saml:Assertion/saml:Subject/saml:NameID')->item(0);
        if ($subjectNode) {
            $claims->sub = trim($subjectNode->nodeValue);
            $claims->user_id = $claims->sub;
            
            // Extract name ID format
            if ($subjectNode->hasAttribute('Format')) {
                $claims->name_id_format = $subjectNode->getAttribute('Format');
            }
        }

        // Extract issuer
        $issuerNode = $xpath->query('//saml:Assertion/saml:Issuer')->item(0);
        if ($issuerNode) {
            $claims->iss = trim($issuerNode->nodeValue);
        }

        // Set audience
        $claims->aud = $this->audience;

        // Extract time claims
        $conditionsNode = $xpath->query('//saml:Assertion/saml:Conditions')->item(0);
        if ($conditionsNode) {
            if ($conditionsNode->hasAttribute('NotBefore')) {
                $claims->nbf = (new DateTime($conditionsNode->getAttribute('NotBefore')))->getTimestamp();
            }
            if ($conditionsNode->hasAttribute('NotOnOrAfter')) {
                $claims->exp = (new DateTime($conditionsNode->getAttribute('NotOnOrAfter')))->getTimestamp();
            }
        }

        // Set issued at time
        $claims->iat = time();

        // Extract attributes
        $this->extractAttributes($xpath, $claims);

        // Extract authentication context
        $this->extractAuthenticationContext($xpath, $claims);

        return $claims;
    }

    /**
     * Extract SAML attributes
     */
    private function extractAttributes(DOMXPath $xpath, stdClass $claims): void
    {
        $attributeNodes = $xpath->query('//saml:Assertion/saml:AttributeStatement/saml:Attribute');
        
        $groups = [];
        $roles = [];
        
        foreach ($attributeNodes as $attributeNode) {
            $attributeName = $attributeNode->getAttribute('Name');
            $attributeValues = [];

            $valueNodes = $xpath->query('.//saml:AttributeValue', $attributeNode);
            foreach ($valueNodes as $valueNode) {
                $value = trim($valueNode->nodeValue);
                if (!empty($value)) {
                    $attributeValues[] = $value;
                }
            }

            // Map common attributes to standard claims
            switch (strtolower($attributeName)) {
                case 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress':
                case 'email':
                case 'mail':
                    $claims->email = $attributeValues[0] ?? null;
                    break;

                case 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname':
                case 'givenname':
                case 'firstname':
                    $claims->given_name = $attributeValues[0] ?? null;
                    break;

                case 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname':
                case 'surname':
                case 'lastname':
                    $claims->family_name = $attributeValues[0] ?? null;
                    break;

                case 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name':
                case 'displayname':
                case 'name':
                    $claims->name = $attributeValues[0] ?? null;
                    break;

                case 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups':
                case 'groups':
                case 'memberof':
                    $groups = array_merge($groups, $attributeValues);
                    break;

                case 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role':
                case 'roles':
                case 'role':
                    $roles = array_merge($roles, $attributeValues);
                    break;

                case 'department':
                    $claims->department = $attributeValues[0] ?? null;
                    break;

                case 'title':
                    $claims->title = $attributeValues[0] ?? null;
                    break;

                default:
                    // Store unknown attributes with their original name
                    $claims->{$attributeName} = count($attributeValues) === 1 ? $attributeValues[0] : $attributeValues;
                    break;
            }
        }

        // Set groups and roles
        if (!empty($groups)) {
            $claims->groups = array_unique($groups);
        }
        if (!empty($roles)) {
            $claims->roles = array_unique($roles);
        }

        // Build full name if parts are available
        if (empty($claims->name ?? null) && 
            (!empty($claims->given_name ?? null) || !empty($claims->family_name ?? null))) {
            $claims->name = trim(($claims->given_name ?? '') . ' ' . ($claims->family_name ?? ''));
        }
    }

    /**
     * Extract authentication context information
     */
    private function extractAuthenticationContext(DOMXPath $xpath, stdClass $claims): void
    {
        $authStmtNode = $xpath->query('//saml:Assertion/saml:AuthnStatement')->item(0);
        
        if ($authStmtNode) {
            // Authentication time
            if ($authStmtNode->hasAttribute('AuthnInstant')) {
                $claims->auth_time = (new DateTime($authStmtNode->getAttribute('AuthnInstant')))->getTimestamp();
            }

            // Session index
            if ($authStmtNode->hasAttribute('SessionIndex')) {
                $claims->session_index = $authStmtNode->getAttribute('SessionIndex');
            }

            // Authentication context
            $authnContextNode = $xpath->query('.//saml:AuthnContext/saml:AuthnContextClassRef', $authStmtNode)->item(0);
            if ($authnContextNode) {
                $claims->acr = trim($authnContextNode->nodeValue);
            }
        }
    }
}