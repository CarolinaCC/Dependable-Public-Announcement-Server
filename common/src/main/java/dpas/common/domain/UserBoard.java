package dpas.common.domain;

import dpas.common.domain.exception.InvalidUserException;
import dpas.common.domain.exception.NullAnnouncementException;
import dpas.common.domain.exception.NullUserException;

public class UserBoard extends AnnouncementBoard {
	private User _owner;

	public UserBoard(User user) throws NullUserException {
		if (user == null)
			throw new NullUserException("Invalid User: Cannot be null");
		_owner = user;
		_publicKey = user.getPublicKey();
	}

	@Override
	public synchronized void post(Announcement announcement) throws NullAnnouncementException, InvalidUserException {
		checkArguments(announcement);
		_posts.add(announcement);
	}

	private void checkArguments(Announcement post) throws NullAnnouncementException, InvalidUserException {
		if (post == null) {
			throw new NullAnnouncementException("Invalid Post: Cannot be null");
		}
		if (post.getUser() != _owner) {
			throw new InvalidUserException("Invalid User: User is not owner of this board");
		}
	}

}
