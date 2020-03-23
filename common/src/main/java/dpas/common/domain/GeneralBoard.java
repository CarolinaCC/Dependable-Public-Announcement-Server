package dpas.common.domain;

import java.security.PublicKey;

import dpas.common.domain.exception.NullAnnouncementException;

public class GeneralBoard extends AnnouncementBoard {

	public GeneralBoard(PublicKey key) {
		_publicKey = key;
	}
	
	@Override
	public synchronized void post(Announcement announcement) throws NullAnnouncementException {
		if (announcement == null) {
			throw new NullAnnouncementException("Invalid Announcement: Cannot be null");
		}
		_posts.add(announcement);

	}

}
