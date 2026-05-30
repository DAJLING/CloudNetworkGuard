const COUNTRY_PROFILES = {
  US: { timeZone: 'America/New_York', windowsTimeZone: 'Eastern Standard Time', language: 'en-US' },
  GB: { timeZone: 'Europe/London', windowsTimeZone: 'GMT Standard Time', language: 'en-GB' },
  CA: { timeZone: 'America/Toronto', windowsTimeZone: 'Eastern Standard Time', language: 'en-CA' },
  AU: { timeZone: 'Australia/Sydney', windowsTimeZone: 'AUS Eastern Standard Time', language: 'en-AU' },
  DE: { timeZone: 'Europe/Berlin', windowsTimeZone: 'W. Europe Standard Time', language: 'de-DE' },
  JP: { timeZone: 'Asia/Tokyo', windowsTimeZone: 'Tokyo Standard Time', language: 'ja-JP' }
};

const US_REGION_RULES = [
  {
    keywords: ['alaska'],
    timeZone: 'America/Anchorage',
    windowsTimeZone: 'Alaskan Standard Time'
  },
  {
    keywords: ['hawaii'],
    timeZone: 'Pacific/Honolulu',
    windowsTimeZone: 'Hawaiian Standard Time'
  },
  {
    keywords: [
      'california',
      'washington',
      'oregon',
      'nevada',
      'pacific',
      'arizona',
      'los angeles',
      'seattle'
    ],
    timeZone: 'America/Los_Angeles',
    windowsTimeZone: 'Pacific Standard Time'
  },
  {
    keywords: ['colorado', 'montana', 'utah', 'wyoming', 'new mexico', 'idaho', 'mountain', 'denver'],
    timeZone: 'America/Denver',
    windowsTimeZone: 'Mountain Standard Time'
  },
  {
    keywords: [
      'alabama',
      'arkansas',
      'illinois',
      'iowa',
      'louisiana',
      'minnesota',
      'mississippi',
      'missouri',
      'oklahoma',
      'texas',
      'wisconsin',
      'kansas',
      'nebraska',
      'north dakota',
      'south dakota',
      'central',
      'chicago',
      'houston'
    ],
    timeZone: 'America/Chicago',
    windowsTimeZone: 'Central Standard Time'
  },
  {
    keywords: [
      'indiana',
      'georgia',
      'florida',
      'new york',
      'ohio',
      'pennsylvania',
      'michigan',
      'north carolina',
      'virginia',
      'eastern',
      'massachusetts',
      'new jersey',
      'maryland',
      'connecticut'
    ],
    timeZone: 'America/New_York',
    windowsTimeZone: 'Eastern Standard Time'
  }
];

function normalizeRegion(regionName) {
  return String(regionName || '')
    .trim()
    .toLowerCase();
}

function resolveUsRegion(regionName) {
  const normalized = normalizeRegion(regionName);
  if (!normalized) return null;

  for (const rule of US_REGION_RULES) {
    if (rule.keywords.some((keyword) => normalized.includes(keyword))) {
      return {
        timeZone: rule.timeZone,
        windowsTimeZone: rule.windowsTimeZone,
        language: 'en-US'
      };
    }
  }

  return null;
}

function resolveCountryProfile(countryCode, regionName) {
  const code = String(countryCode || '')
    .trim()
    .toUpperCase();

  if (code === 'US') {
    const usRegion = resolveUsRegion(regionName);
    if (usRegion) return { ...usRegion, countryCode: 'US', derivedFrom: 'exit-ip' };
    return { ...COUNTRY_PROFILES.US, countryCode: 'US', derivedFrom: 'exit-ip' };
  }

  if (COUNTRY_PROFILES[code]) {
    return { ...COUNTRY_PROFILES[code], countryCode: code, derivedFrom: 'exit-ip' };
  }

  return { ...COUNTRY_PROFILES.US, countryCode: code || 'US', derivedFrom: 'fallback' };
}

function buildProfile(base, override = {}) {
  const timeZone = String(override.timeZone || '').trim() || base.timeZone;
  const language = String(override.language || '').trim() || base.language;
  const languages =
    Array.isArray(override.languages) && override.languages.length
      ? override.languages.map((item) => String(item).trim()).filter(Boolean)
      : [language];

  const hasOverride = Boolean(override.timeZone || override.language || (override.languages && override.languages.length));

  return {
    timeZone,
    windowsTimeZone: base.windowsTimeZone,
    language,
    languages,
    countryCode: base.countryCode,
    derivedFrom: hasOverride ? 'override' : base.derivedFrom
  };
}

function resolveEnvironmentProfile(exitIp = {}, override = {}) {
  const base = resolveCountryProfile(exitIp.countryCode, exitIp.regionName);
  const profile = buildProfile(base, override);

  if (override.timeZone) {
    profile.windowsTimeZone = mapIanaToWindows(profile.timeZone) || base.windowsTimeZone;
  }

  return profile;
}

function mapIanaToWindows(ianaTimeZone) {
  const map = {
    'America/New_York': 'Eastern Standard Time',
    'America/Chicago': 'Central Standard Time',
    'America/Denver': 'Mountain Standard Time',
    'America/Los_Angeles': 'Pacific Standard Time',
    'America/Anchorage': 'Alaskan Standard Time',
    'Pacific/Honolulu': 'Hawaiian Standard Time',
    'Europe/London': 'GMT Standard Time',
    'Europe/Berlin': 'W. Europe Standard Time',
    'America/Toronto': 'Eastern Standard Time',
    'Australia/Sydney': 'AUS Eastern Standard Time',
    'Asia/Tokyo': 'Tokyo Standard Time'
  };
  return map[ianaTimeZone] || null;
}

module.exports = {
  COUNTRY_PROFILES,
  US_REGION_RULES,
  resolveEnvironmentProfile,
  resolveUsRegion,
  mapIanaToWindows
};
