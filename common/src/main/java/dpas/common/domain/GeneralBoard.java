package dpas.common.domain;

import dpas.common.domain.exception.NullPostException;
import dpas.common.domain.exception.NullUserException;
import dpas.common.domain.exception.InvalidNumberOfPostsException;
import java.util.ArrayList;

public class GeneralBoard implements AnnouncementBoard {
    public ArrayList<Announcement> _posts;

    @Override

    public void post(User user, Announcement announcement) throws NullPostException, NullUserException {
         checkArguments(user, announcement);
        _posts.add(announcement);
    }

    public void checkArguments(User user, Announcement post) throws NullUserException, NullPostException  {
        if (user == null) {
            throw new NullUserException();
        }
        if (post == null) {
            throw new NullPostException();
        }
    }

    @Override
    public ArrayList<Announcement> read(int number) throws InvalidNumberOfPostsException {
        if (number < 0 || number > _posts.size())
            throw new InvalidNumberOfPostsException();
        if (number == 0)
            return new ArrayList<>(_posts);
        return new ArrayList<Announcement>(_posts.subList(_posts.size()-number, _posts.size()));
    }
}
