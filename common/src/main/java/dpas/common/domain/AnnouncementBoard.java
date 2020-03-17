package dpas.common.domain;

import dpas.common.domain.exception.*;

import java.io.Serializable;
import java.util.ArrayList;

public abstract class AnnouncementBoard {
    protected ArrayList<Announcement> _posts = new ArrayList<>();

    public abstract void post(Announcement announcement) throws NullAnnouncementException, NullUserException, InvalidUserException;

    public ArrayList<Announcement> read(int number) throws InvalidNumberOfPostsException {
        if (number < 0)
            throw new InvalidNumberOfPostsException();
        if (number == 0 || number >= _posts.size())
            return new ArrayList<>(_posts);
        return new ArrayList<Announcement>(_posts.subList(_posts.size() - number, _posts.size()));
    }

    public Announcement getAnnouncementFromReference(int reference) throws InvalidReferenceException {
        if (reference < 0 || _posts.size() <= reference) {
            throw new InvalidReferenceException();
        }
        return _posts.get(reference);
    }

}
