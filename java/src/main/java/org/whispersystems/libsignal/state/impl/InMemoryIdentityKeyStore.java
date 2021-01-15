/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state.impl;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.IdentityKeyStore;

import java.util.HashMap;
import java.util.Map;

public class InMemoryIdentityKeyStore implements IdentityKeyStore {

  private final Map<SignalProtocolAddress, IdentityKey> trustedKeys = new HashMap<>();

  private final IdentityKeyPair identityKeyPair;
  private final int             localRegistrationId;

  public InMemoryIdentityKeyStore(IdentityKeyPair identityKeyPair, int localRegistrationId) {
    this.identityKeyPair     = identityKeyPair;
    this.localRegistrationId = localRegistrationId;
  }

  @Override
  public IdentityKeyPair getIdentityKeyPair() {
    return identityKeyPair;
  }

  @Override
  public int getLocalRegistrationId() {
    return localRegistrationId;
  }

  @Override
  public boolean saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
    IdentityKey existing = trustedKeys.get(address);

    /* ********OpenRefactory Warning********
	 Possible null pointer Dereference!
	 Path: 
		File: SessionCipher.java, Line: 125
			identityKeyStore.saveIdentity(remoteAddress,sessionState.getRemoteIdentityKey());
			 Information is passed through the method call via sessionState.getRemoteIdentityKey() to the formal param identityKey of the method. This later results into a null pointer dereference.
		File: InMemorySignalProtocolStore.java, Line: 42
			IdentityKey identityKey
			Variable identityKey is declared as a formal parameter.
		File: InMemorySignalProtocolStore.java, Line: 43
			return identityKeyStore.saveIdentity(address,identityKey);
			 Information is passed through the method call via identityKey to the formal param identityKey of the method. This later results into a null pointer dereference.
		File: InMemoryIdentityKeyStore.java, Line: 42
			identityKey.equals(existing)
			identityKey is referenced in method invocation.
			The expression is enclosed inside an If statement.
	 Fix:
			identityKey is identified as null, but the argument passed to
			the equals method is not. 
			iCR fixes by calling equals method in the context of
			the non-null expression. 
	
	*/
	if (!existing.equals(identityKey)) {
      trustedKeys.put(address, identityKey);
      return true;
    } else {
      return false;
    }
  }

  @Override
  public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction) {
    IdentityKey trusted = trustedKeys.get(address);
    return (trusted == null || trusted.equals(identityKey));
  }

  @Override
  public IdentityKey getIdentity(SignalProtocolAddress address) {
    return trustedKeys.get(address);
  }
}
