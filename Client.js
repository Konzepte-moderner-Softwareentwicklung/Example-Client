// Utility functions for base64url encoding/decoding
const bufferToBase64Url = (buffer) => {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
};

const base64UrlToBuffer = (base64url) => {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const str = atob(base64);
  const buffer = new ArrayBuffer(str.length);
  const byteView = new Uint8Array(buffer);
  
  for (let i = 0; i < str.length; i++) {
    byteView[i] = str.charCodeAt(i);
  }
  
  return buffer;
};

class WebAuthnService {
  constructor() {
    this.authToken = null;
  }

  setAuthToken(token) {
    this.authToken = token;
  }

  async getRegistrationOptions() {
    const response = await fetch("/api/user/webauthn/register/options", {
      headers: {
        Authorization: this.authToken,
      },
      credentials: "include",
      mode: "cors",
    });

    const rawResponse = await response.text();
    let options;
    
    try {
      options = JSON.parse(rawResponse);
    } catch (e) {
      throw new Error(`Failed to parse server response as JSON: ${e.message}`);
    }

    if (!options) {
      throw new Error("Server returned empty options");
    }

    if (!options.publicKey) {
      throw new Error("Server response missing publicKey object");
    }

    options = options.publicKey;

    if (!options.challenge) {
      throw new Error("Server response missing challenge");
    }

    if (!options.rp) {
      throw new Error("Server response missing rp (relying party) information");
    }

    if (!options.user) {
      throw new Error("Server response missing user information");
    }

    // Convert base64url challenge to ArrayBuffer
    options.challenge = base64UrlToBuffer(options.challenge);

    // Convert user.id from base64url to ArrayBuffer if it exists
    if (options.user?.id) {
      options.user.id = base64UrlToBuffer(options.user.id);
    }

    // Convert any existing credentials to ArrayBuffer
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map((cred) => ({
        ...cred,
        id: base64UrlToBuffer(cred.id),
      }));
    }

    return options;
  }

  async register() {
    if (!this.authToken) {
      throw new Error("Please login first");
    }

    const options = await this.getRegistrationOptions();
    const credential = await navigator.credentials.create({
      publicKey: options,
    });

    const credentialData = {
      id: credential.id,
      rawId: bufferToBase64Url(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: bufferToBase64Url(credential.response.attestationObject),
        clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
      },
    };

    const response = await fetch("/api/user/webauthn/register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: this.authToken,
      },
      credentials: "include",
      mode: "cors",
      body: JSON.stringify(credentialData),
    });

    return await response.text();
  }

  async getLoginOptions(email) {
    const response = await fetch(
      `/api/user/webauthn/login/options?email=${encodeURIComponent(email)}`,
      {
        credentials: "include",
        mode: "cors",
      },
    );

    const rawResponse = await response.text();
    let options;
    
    try {
      options = JSON.parse(rawResponse);
    } catch (e) {
      throw new Error(`Failed to parse server response as JSON: ${e.message}`);
    }

    if (!options) {
      throw new Error("Server returned empty options");
    }

    if (!options.publicKey) {
      throw new Error("Server response missing publicKey object");
    }

    options = options.publicKey;

    if (!options.challenge) {
      throw new Error("Server response missing challenge");
    }

    // Convert base64url challenge to ArrayBuffer
    options.challenge = base64UrlToBuffer(options.challenge);

    // Convert any existing credentials to ArrayBuffer
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map((cred) => ({
        ...cred,
        id: base64UrlToBuffer(cred.id),
      }));
    }

    return options;
  }

  async login(email) {
    if (!email) {
      throw new Error("Please enter your email");
    }

    const options = await this.getLoginOptions(email);
    const assertion = await navigator.credentials.get({ publicKey: options });

    const assertionData = {
      id: assertion.id,
      rawId: bufferToBase64Url(assertion.rawId),
      type: assertion.type,
      response: {
        authenticatorData: bufferToBase64Url(assertion.response.authenticatorData),
        clientDataJSON: bufferToBase64Url(assertion.response.clientDataJSON),
        signature: bufferToBase64Url(assertion.response.signature),
        userHandle: assertion.response.userHandle
          ? bufferToBase64Url(assertion.response.userHandle)
          : null,
      },
    };

    const response = await fetch(
      `/api/user/webauthn/login?email=${encodeURIComponent(email)}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: "include",
        mode: "cors",
        body: JSON.stringify(assertionData),
      },
    );

    return await response.text();
  }
}

class Client {
  constructor() {
    this.base_url = "/api";
    this.user_url = `${this.base_url}/user`;
    this.offer_url = `${this.base_url}/angebot`;
    this.token = null;
    this.ws = null;
    this.locationIntervalId = null;
  }

  async getOffersByFilter(filter) {
    try {
      const response = await fetch(this.offer_url + "/filter", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(filter),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Error fetching offers: ${response.status} ${errorText}`);
      }

      return await response.json();
    } catch (error) {
      console.error("Failed to get offers by filter:", error);
      throw error;
    }
  }

  async createOffer(angebot) {
    const response = await fetch(`${this.offer_url}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: this.token,
      },
      credentials: "include",
      body: JSON.stringify(angebot),
    });

    if (!response.ok) {
      throw new Error("Failed to create offer");
    }

    return await response.json();
  }

  async getOfferById(id) {
    const response = await fetch(`${this.offer_url}/${id}`, {
      method: "GET",
    });

    if (!response.ok) {
      throw new Error("Failed to get offer");
    }

    return await response.json();
  }

  async getUsers() {
    const response = await fetch(`${this.user_url}`);
    return response.json();
  }

  async getUserByEmail(email) {
    const response = await fetch(`${this.user_url}/email?email=${email}`);
    return response.json();
  }

  async getUserById(id) {
    const response = await fetch(`${this.user_url}/${id}`);
    return response.json();
  }

  async createUser(user) {
    const response = await fetch(`${this.user_url}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(user),
    });
    return response.json();
  }

  async login(email, password) {
    const response = await fetch(`${this.user_url}/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Login failed: ${response.status} ${errorText}`);
    }

    const data = await response.json();
    this.token = data.token;

    this.connectWebSocket();

    // Optional: pass token to WebAuthnService
    const webauthn = new WebAuthnService();
    webauthn.setAuthToken(this.token);
  }

  async connectWebSocket() {
    this.ws = new WebSocket(`/api/ws?token=${encodeURI(this.token)}`);
    
    this.ws.onopen = () => {
      console.log("WebSocket connection established");
    };
    
    this.ws.onmessage = (event) => {
      console.log("Received message:", event.data);
    };
    
    this.ws.onclose = () => {
      console.log("WebSocket connection closed");
    };
  }

  async loginPasskey(email) {
    const webauthn = new WebAuthnService();
    const options = await webauthn.getLoginOptions(email);
    const assertion = await navigator.credentials.get({ publicKey: options });

    const assertionData = {
      id: assertion.id,
      rawId: bufferToBase64Url(assertion.rawId),
      type: assertion.type,
      response: {
        authenticatorData: bufferToBase64Url(assertion.response.authenticatorData),
        clientDataJSON: bufferToBase64Url(assertion.response.clientDataJSON),
        signature: bufferToBase64Url(assertion.response.signature),
        userHandle: assertion.response.userHandle
          ? bufferToBase64Url(assertion.response.userHandle)
          : null,
      },
    };

    const response = await fetch(
      `${this.user_url}/webauthn/login?email=${encodeURIComponent(email)}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: "include",
        mode: "cors",
        body: JSON.stringify(assertionData),
      },
    );

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`WebAuthn login failed: ${response.status} ${errorText}`);
    }

    const data = await response.json();
    this.token = data.token;

    this.connectWebSocket();
  }

  async registerPasskey() {
    const webauthn = new WebAuthnService();
    webauthn.setAuthToken(this.token);
    await webauthn.register();
  }

  async logout() {
    this.token = null;
    this.ws.close();
  }

  registerOnMessage(onMessage) {
    this.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (typeof this.onMessage === "function") {
          this.onMessage(msg);
        }
      } catch (err) {
        console.error("Invalid message format", event.data);
      }
    };
  }

  registerOnClose(onClose) {
    this.ws.onclose = onClose;
  }

  registerOnOpen(onOpen) {
    this.ws.onopen = onOpen;
  }
}

// Builder Classes
class UserBuilder {
  constructor() {
    this.requiredFields = {
      firstName: null,
      lastName: null,
      email: null,
      password: null,
    };

    this.optionalFields = {
      birthDate: null,
      phoneNumber: null,
      profilePicture: null,
    };
  }

  setFirstName(firstName) {
    this.requiredFields.firstName = firstName;
    return this;
  }

  setLastName(lastName) {
    this.requiredFields.lastName = lastName;
    return this;
  }

  setEmail(email) {
    this.requiredFields.email = email;
    return this;
  }

  setPassword(password) {
    this.requiredFields.password = password;
    return this;
  }

  setBirthDate(date) {
    this.optionalFields.birthDate = new Date(date).toISOString();
    return this;
  }

  setPhoneNumber(phoneNumber) {
    this.optionalFields.phoneNumber = phoneNumber;
    return this;
  }

  setProfilePicture(url) {
    this.optionalFields.profilePicture = url;
    return this;
  }

  build() {
    const missingFields = Object.entries(this.requiredFields)
      .filter(([_, value]) => !value)
      .map(([key]) => key);

    if (missingFields.length > 0) {
      throw new Error(`Missing required fields: ${missingFields.join(", ")}`);
    }

    return {
      ...this.requiredFields,
      ...this.optionalFields,
    };
  }
}

class SizeBuilder {
  constructor() {
    this.size = {};
  }

  setWidth(width) {
    this.size.width = width;
    return this;
  }

  setHeight(height) {
    this.size.height = height;
    return this;
  }

  setDepth(depth) {
    this.size.depth = depth;
    return this;
  }

  build() {
    if (
      this.size.width === undefined ||
      this.size.height === undefined ||
      this.size.depth === undefined
    ) {
      throw new Error("Size: width, height and depth are required.");
    }
    return this.size;
  }
}

class LocationBuilder {
  constructor() {
    this.location = {};
  }

  setLongitude(longitude) {
    this.location.longitude = longitude;
    return this;
  }

  setLatitude(latitude) {
    this.location.latitude = latitude;
    return this;
  }

  build() {
    if (
      this.location.longitude === undefined ||
      this.location.latitude === undefined
    ) {
      throw new Error("Location: longitude and latitude are required.");
    }
    return this.location;
  }
}

class ItemBuilder {
  constructor() {
    this.item = {};
  }

  setSize(sizeBuilder) {
    this.item.size = sizeBuilder.build();
    return this;
  }

  setWeight(weight) {
    this.item.weight = weight;
    return this;
  }

  build() {
    if (!this.item.size) {
      throw new Error("Item: size is required.");
    }
    if (this.item.weight === undefined) {
      throw new Error("Item: weight is required.");
    }
    return this.item;
  }
}

class SpaceBuilder {
  constructor() {
    this.space = { items: [] };
  }

  addItem(itemBuilder) {
    this.space.items.push(itemBuilder.build());
    return this;
  }

  setSeats(seats) {
    this.space.seats = seats;
    return this;
  }

  build() {
    if (this.space.seats === undefined) {
      throw new Error("Space: seats is required.");
    }
    return this.space;
  }
}

class OfferBuilder {
  constructor() {
    this.offer = {};
  }

  setTitle(title) {
    this.offer.title = title;
    return this;
  }

  setDescription(desc) {
    this.offer.description = desc;
    return this;
  }

  setPrice(price) {
    this.offer.price = price;
    return this;
  }

  setLocationFrom(location) {
    this.offer.locationFrom = location;
    return this;
  }

  setLocationTo(location) {
    this.offer.locationTo = location;
    return this;
  }

  setCreatedAt(date) {
    this.offer.createdAt = date;
    return this;
  }

  setIsChat(isChat) {
    this.offer.isChat = isChat;
    return this;
  }

  setChatId(chatId) {
    this.offer.chatId = chatId;
    return this;
  }

  setIsPhone(isPhone) {
    this.offer.isPhone = isPhone;
    return this;
  }

  setIsEmail(isEmail) {
    this.offer.isEmail = isEmail;
    return this;
  }

  setStartDateTime(date) {
    this.offer.startDateTime = date;
    return this;
  }

  setEndDateTime(date) {
    this.offer.endDateTime = date;
    return this;
  }

  setCanTransport(spaceBuilder) {
    this.offer.canTransport = spaceBuilder;
    return this;
  }

  setRestrictions(restrictions) {
    this.offer.restrictions = restrictions;
    return this;
  }

  setInfo(info) {
    this.offer.info = info;
    return this;
  }

  setInfoCar(infoCar) {
    this.offer.infoCar = infoCar;
    return this;
  }

  build() {
    const requiredFields = [
      "title",
      "price",
      "locationFrom",
      "locationTo",
      "startDateTime",
      "endDateTime",
      "canTransport",
    ];

    for (const field of requiredFields) {
      if (this.offer[field] === undefined || this.offer[field] === null) {
        throw new Error(`Offer: field '${field}' is required.`);
      }
    }

    return this.offer;
  }
}

class FilterBuilder {
  constructor() {
    this.filter = {};
  }

  setNameStartsWith(prefix) {
    this.filter.nameStartsWith = prefix;
    return this;
  }

  setSpaceNeeded(spaceBuilder) {
    this.filter.spaceNeeded = spaceBuilder?.build ? spaceBuilder.build() : spaceBuilder;
    return this;
  }

  setLocationFrom(locationBuilder) {
    this.filter.locationFrom = locationBuilder?.build ? locationBuilder.build() : locationBuilder;
    return this;
  }

  setLocationTo(locationBuilder) {
    this.filter.locationTo = locationBuilder?.build ? locationBuilder.build() : locationBuilder;
    return this;
  }

  setLocationFromDiff(diff) {
    this.filter.locationFromDiff = diff;
    return this;
  }

  setLocationToDiff(diff) {
    this.filter.locationToDiff = diff;
    return this;
  }

  setUser(uuidString) {
    this.filter.user = uuidString;
    return this;
  }

  setCreator(uuidString) {
    this.filter.creator = uuidString;
    return this;
  }

  setCurrentTime(date) {
    this.filter.currentTime = date instanceof Date ? date.toISOString() : date;
    return this;
  }

  build() {
    return this.filter;
  }
}

// Export classes and create default client instance
window.WebAuthnService = WebAuthnService;
const client = new Client();

// Example usage
const loc = new LocationBuilder()
  .setLongitude(12.3456)
  .setLatitude(78.9012)
  .build();

const offer = new OfferBuilder()
  .setTitle("My Offer")
  .setPrice(100)
  .setLocationFrom(loc)
  .setLocationTo(loc)
  .setStartDateTime(new Date())
  .setEndDateTime(new Date().setHours(new Date().getHours() + 10))
  .setCanTransport(new SpaceBuilder().setSeats(5).build())
  .build();
