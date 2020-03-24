package dpas.common.domain;

import java.util.ArrayList;

import dpas.common.domain.exception.InvalidNumberOfPostsException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.common.domain.exception.NullAnnouncementException;
import dpas.common.domain.exception.NullUserException;

public abstract class AnnouncementBoard {
	protected ArrayList<Announcement> _posts = new ArrayList<>();
	
	public abstract String getIdentifier();

	public abstract void post(Announcement announcement)
			throws NullAnnouncementException, NullUserException, InvalidUserException;

	public ArrayList<Announcement> read(int number) throws InvalidNumberOfPostsException {
		if (number < 0)
			throw new InvalidNumberOfPostsException("Invalid number of posts to read: number cannot be negative");
		if (number == 0 || number >= _posts.size())
			return new ArrayList<>(_posts);
		return new ArrayList<>(_posts.subList(_posts.size() - number, _posts.size()));
	}

}
