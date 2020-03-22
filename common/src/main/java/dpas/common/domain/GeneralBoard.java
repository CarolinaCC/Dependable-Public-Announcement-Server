package dpas.common.domain;

import dpas.common.domain.exception.NullAnnouncementException;

public class GeneralBoard extends AnnouncementBoard {

	@Override
	public void post(Announcement announcement) throws NullAnnouncementException {
		if (announcement == null) {
			throw new NullAnnouncementException("Invalid Announcement: Cannot be null");
		}
		_posts.add(announcement);

	}

}
